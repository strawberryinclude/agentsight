/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Unit tests for process_ext/content.h (user-space half of content hashing):
 *   - SHA-256 against FIPS 180-4 / known vectors, incl. chunked updates
 *   - content_hash_file(): ok, inode mismatch, path gone, size limit
 *   - kernel event flow: before_write, write close + debounce -> after_write,
 *     rename (atomic replace) and unlink, checked on the JSON output
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/bpf.h>

#include "process.h"
#include "jsonl.h"
#include "process_ext/content.h"

static int failures;

#define CHECK(cond, ...) do {                                       \
	if (!(cond)) {                                              \
		failures++;                                         \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);\
		fprintf(stderr, __VA_ARGS__);                       \
		fprintf(stderr, "\n");                              \
	}                                                           \
} while (0)

static void sha_hex(const void *data, size_t len, size_t chunk, char out[65])
{
	struct content_sha256 ctx;
	uint8_t digest[32];
	const uint8_t *p = data;

	content_sha256_init(&ctx);
	while (len) {
		size_t n = chunk && chunk < len ? chunk : len;
		content_sha256_update(&ctx, p, n);
		p += n;
		len -= n;
	}
	content_sha256_final(&ctx, digest);
	content_hex(digest, 32, out);
}

static void test_sha256_vectors(void)
{
	static const char *two_blocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	char hex[65];
	char *million;

	sha_hex("", 0, 0, hex);
	CHECK(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "empty: %s", hex);
	sha_hex("abc", 3, 0, hex);
	CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "abc: %s", hex);
	for (size_t chunk = 0; chunk <= 64; chunk += 7) {
		sha_hex(two_blocks, strlen(two_blocks), chunk, hex);
		CHECK(!strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
		      "448-bit message chunk %zu: %s", chunk, hex);
	}
	/* The exact content and digest from the VM experiment (`echo hello`). */
	sha_hex("hello\n", 6, 0, hex);
	CHECK(!strcmp(hex, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"), "hello: %s", hex);

	million = malloc(1000000);
	memset(million, 'a', 1000000);
	sha_hex(million, 1000000, 4096 + 3, hex);
	CHECK(!strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "1M a: %s", hex);
	free(million);
}

static uint32_t kernel_dev_of(const struct stat *st)
{
	return (uint32_t)(major(st->st_dev) << 20 | minor(st->st_dev));
}

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	fputs(content, f);
	fclose(f);
}

static void test_hash_file(const char *dir)
{
	char path[512], hex[65];
	struct stat st, out;
	int err = 0, status;

	snprintf(path, sizeof(path), "%s/a.txt", dir);
	write_file(path, "hello\n");
	stat(path, &st);

	status = content_hash_file(0, path, kernel_dev_of(&st), st.st_ino, 1024, hex, &out, &err);
	CHECK(status == CONTENT_US_OK, "ok status %d err %d", status, err);
	CHECK(!strcmp(hex, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"), "file hash %s", hex);

	status = content_hash_file(0, path, kernel_dev_of(&st), st.st_ino + 1, 1024, hex, &out, &err);
	CHECK(status == CONTENT_US_INODE_MISMATCH, "mismatch status %d", status);

	status = content_hash_file(0, path, kernel_dev_of(&st), st.st_ino, 3, hex, &out, &err);
	CHECK(status == CONTENT_US_TOO_LARGE, "too large status %d", status);

	snprintf(path, sizeof(path), "%s/missing.txt", dir);
	status = content_hash_file(0, path, kernel_dev_of(&st), st.st_ino, 1024, hex, &out, &err);
	CHECK(status == CONTENT_US_PATH_GONE, "gone status %d", status);

	status = content_hash_file(0, NULL, 0, 1, 1024, hex, &out, &err);
	CHECK(status == CONTENT_US_UNKNOWN_PATH, "unknown status %d", status);
}

static struct event make_event(int kind, const char *path, const struct stat *st)
{
	struct event e;

	memset(&e, 0, sizeof(e));
	e.type = EVENT_TYPE_FILE_CONTENT;
	e.pid = 0;  /* skip /proc/<pid>/root in the test */
	strcpy(e.comm, "agent");
	e.timestamp_ns = 1;
	e.content.kind = kind;
	e.content.dev = kernel_dev_of(st);
	e.content.ino = st->st_ino;
	e.content.size = st->st_size;
	if (path)
		snprintf(e.content.filepath, sizeof(e.content.filepath), "%s", path);
	return e;
}

static char *read_all(const char *path)
{
	FILE *f = fopen(path, "r");
	static char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	buf[n] = '\0';
	fclose(f);
	return buf;
}

static void test_event_flow(const char *dir)
{
	char target[512], tmp[512], log[512], expected[128];
	struct stat st_target, st_tmp;
	struct event e;
	char *out;
	FILE *saved;
	int saved_fd;

	snprintf(target, sizeof(target), "%s/notes.md", dir);
	snprintf(tmp, sizeof(tmp), "%s/.notes.md.tmp", dir);
	snprintf(log, sizeof(log), "%s/out.jsonl", dir);
	write_file(target, "hello\n");
	stat(target, &st_target);

	content_enabled = true;
	content_max_bytes = 1 << 20;

	/* Redirect stdout to capture the JSON lines. */
	fflush(stdout);
	saved_fd = dup(STDOUT_FILENO);
	saved = freopen(log, "w", stdout);
	(void)saved;

	/* 1. Kernel measured the target before its first write. */
	e = make_event(CONTENT_KIND_PRE_WRITE, target, &st_target);
	e.content.hash_status = CONTENT_HASH_OK;
	e.content.hash_algo = CONTENT_IMA_ALGO_SHA256;
	for (int i = 0; i < 32; i++) {
		unsigned v;
		sscanf("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" + i * 2, "%2x", &v);
		e.content.hash[i] = (unsigned char)v;
	}
	content_on_kernel_event(&e);

	/* 2. In-place edit, then close: after_write only after the debounce. */
	write_file(target, "hello\nmore\n");
	e = make_event(CONTENT_KIND_WRITE_CLOSE, NULL, &st_target);
	content_on_kernel_event(&e);
	CHECK(content_dirty_count == 1, "dirty count %d", content_dirty_count);
	content_flush_dirty(false);  /* inside the debounce window: nothing yet */
	CHECK(content_dirty_count == 1, "debounce kept dirty, count %d", content_dirty_count);
	content_flush_dirty(true);
	CHECK(content_dirty_count == 0, "flushed, count %d", content_dirty_count);

	/* 3. Atomic replace: temp file renamed over the target. */
	write_file(tmp, "reset\n");
	stat(tmp, &st_tmp);
	e = make_event(CONTENT_KIND_PRE_WRITE, tmp, &st_tmp);
	e.content.hash_status = CONTENT_HASH_CREATED;
	content_on_kernel_event(&e);
	rename(tmp, target);
	e = make_event(CONTENT_KIND_RENAME, target, &st_tmp);
	e.content.replaced_ino = st_target.st_ino;
	content_on_kernel_event(&e);
	content_flush_dirty(true);

	/* 4. Unlink. */
	e = make_event(CONTENT_KIND_UNLINK, target, &st_tmp);
	content_on_kernel_event(&e);

	fflush(stdout);
	dup2(saved_fd, STDOUT_FILENO);
	close(saved_fd);
	clearerr(stdout);

	out = read_all(log);
	CHECK(strstr(out, "\"phase\":\"before_write\"") &&
	      strstr(out, "\"sha256\":\"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03\","
			  "\"hash_source\":\"kernel_ima\""),
	      "before_write line missing:\n%s", out);
	/* sha256("hello\nmore\n"), matches the VM experiment's value B. */
	CHECK(strstr(out, "\"phase\":\"after_write\"") &&
	      strstr(out, "6052eef1a76d3ff777269e8a1720524953b74c4d96e4689679c8982699a32beb"),
	      "after_write (B) missing:\n%s", out);
	CHECK(strstr(out, "\"hash_status\":\"created\""), "created missing:\n%s", out);
	snprintf(expected, sizeof(expected), "\"replaced_ino\":%llu", (unsigned long long)st_target.st_ino);
	CHECK(strstr(out, "\"phase\":\"renamed\"") && strstr(out, expected) &&
	      strstr(out, "\"renamed_from\":"), "renamed line missing:\n%s", out);
	/* sha256("reset\n"), matches the VM experiment's value C. */
	CHECK(strstr(out, "560cfb16a87e0e938208c0a072d5f837ffdf842feed4de3c34fd6069a30d3522"),
	      "after rename hash (C) missing:\n%s", out);
	CHECK(strstr(out, "\"phase\":\"deleted\""), "deleted missing:\n%s", out);
}

/* Cases found in review: O_RDWR, inode reuse, exchange, hard links, compaction. */
static void test_edge_cases(const char *dir)
{
	char path[512], other[512], log[512], *out;
	struct stat st, st_other;
	struct event e;
	int saved_fd;
	FILE *ignored;

	snprintf(path, sizeof(path), "%s/rw.txt", dir);
	snprintf(other, sizeof(other), "%s/other.txt", dir);
	snprintf(log, sizeof(log), "%s/edge.jsonl", dir);
	write_file(path, "hello\n");
	write_file(other, "reset\n");
	stat(path, &st);
	stat(other, &st_other);
	content_enabled = true;

	fflush(stdout);
	saved_fd = dup(STDOUT_FILENO);
	ignored = freopen(log, "w", stdout);
	(void)ignored;

	/* O_RDWR without O_TRUNC: kernel cannot hash, user space falls back. */
	e = make_event(CONTENT_KIND_PRE_WRITE, path, &st);
	e.content.hash_status = CONTENT_HASH_RDWR;
	e.content.flags = O_RDWR;
	content_on_kernel_event(&e);

	/* O_RDWR | O_TRUNC: the old content is already gone, no fallback. */
	e = make_event(CONTENT_KIND_PRE_WRITE, other, &st_other);
	e.content.hash_status = CONTENT_HASH_RDWR;
	e.content.flags = O_RDWR | O_TRUNC;
	content_on_kernel_event(&e);

	/* RENAME_EXCHANGE: the replaced inode takes the moved inode's old path. */
	e = make_event(CONTENT_KIND_RENAME, other, &st);
	e.content.replaced_ino = st_other.st_ino;
	e.content.flags = 2;
	content_on_kernel_event(&e);
	{
		struct content_entry *victim = content_lookup(kernel_dev_of(&st_other), st_other.st_ino, false);
		CHECK(victim && !victim->deleted && victim->path && !strcmp(victim->path, path),
		      "exchange should move the victim to %s, got %s", path,
		      victim && victim->path ? victim->path : "(null)");
	}

	/* Unlinking one of two links keeps the inode alive. */
	e = make_event(CONTENT_KIND_UNLINK, path, &st);
	e.content.nlink = 2;
	content_on_kernel_event(&e);
	CHECK(!content_lookup(kernel_dev_of(&st), st.st_ino, false)->deleted, "nlink 2 marked deleted");

	/* Last link gone, then the inode number is reused by a new file. */
	e = make_event(CONTENT_KIND_UNLINK, path, &st);
	e.content.nlink = 1;
	content_on_kernel_event(&e);
	CHECK(content_lookup(kernel_dev_of(&st), st.st_ino, false)->deleted, "nlink 1 not deleted");
	e = make_event(CONTENT_KIND_PRE_WRITE, path, &st);
	e.content.hash_status = CONTENT_HASH_CREATED;
	content_on_kernel_event(&e);
	{
		struct content_entry *reused = content_lookup(kernel_dev_of(&st), st.st_ino, false);
		CHECK(reused && !reused->deleted && reused->pre_hashed, "reused inode not reset");
	}
	e = make_event(CONTENT_KIND_WRITE_CLOSE, NULL, &st);
	content_on_kernel_event(&e);
	CHECK(content_dirty_count == 1, "reused inode release not paired (%d)", content_dirty_count);
	content_flush_dirty(true);

	fflush(stdout);
	dup2(saved_fd, STDOUT_FILENO);
	close(saved_fd);
	clearerr(stdout);
	out = read_all(log);
	CHECK(strstr(out, "\"hash_status\":\"rdwr\"") &&
	      strstr(out, "\"hash_source\":\"userspace_late\""), "rdwr fallback missing:\n%s", out);
	CHECK(strstr(out, "\"exchange\":true"), "exchange flag missing:\n%s", out);
	CHECK(strstr(out, "\"phase\":\"link_removed\",") && strstr(out, "\"remaining_links\":1"),
	      "link_removed missing:\n%s", out);
	{
		/* Exactly one late fallback: the O_TRUNC open must not get one. */
		const char *first = strstr(out, "userspace_late");
		CHECK(first && !strstr(first + 1, "userspace_late"), "O_TRUNC got a late fallback:\n%s", out);
	}

	/* Compaction keeps written/dirty inodes and drops read-only ones. */
	{
		struct content_entry *pinned = content_lookup(1, 1, true);
		pinned->pre_hashed = true;
		for (uint64_t ino = 100; ino < 100 + CONTENT_TABLE_SIZE; ino++) {
			struct content_entry *entry = content_lookup(2, ino, true);
			CHECK(entry != NULL, "table full at ino %llu", (unsigned long long)ino);
			if (!entry)
				break;
			entry->read_hashed = true;
		}
		CHECK(content_lookup(1, 1, false) && content_lookup(1, 1, false)->pre_hashed,
		      "compaction dropped a written inode");
		CHECK(content_used_count < CONTENT_TABLE_SIZE, "table never compacted");
	}
}

int main(void)
{
	char dir[] = "/tmp/content-test-XXXXXX";

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}
	test_sha256_vectors();
	test_hash_file(dir);
	test_event_flow(dir);
	test_edge_cases(dir);

	if (failures) {
		fprintf(stderr, "%d content test(s) failed\n", failures);
		return 1;
	}
	printf("content: all tests passed\n");
	return 0;
}
