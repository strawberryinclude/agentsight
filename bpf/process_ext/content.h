/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_EXT_CONTENT_H
#define __PROCESS_EXT_CONTENT_H

/*
 * User-space half of file content hashing (kernel half: bpf_content.h).
 *
 * The kernel measures the one thing only it can measure race-free: the
 * content right before the agent's first write. Everything else is done here,
 * as close to the kernel event as possible:
 *
 *   phase "read"          first read-only open of an inode by the agent. The
 *                         kernel cannot hash at that hook (see bpf_content.h),
 *                         so we read the file right after the FILE_OPEN event.
 *   phase "before_write"  forwarded kernel hash (hash_source "kernel_ima"). If
 *                         the kernel could not measure the open (O_RDWR, IMA
 *                         error) and it did not truncate, a user-space hash
 *                         labelled "userspace_late" follows.
 *   phase "after_write"   the last reference to a writable open file of the
 *                         inode was released (close, exit, munmap). We wait
 *                         CONTENT_DEBOUNCE_MS without further releases, then
 *                         hash, so a burst of writes costs one hash and the value
 *                         reflects the content after the last write.
 *   phase "renamed"       inode moved to a new path, possibly replacing another
 *                         inode (atomic "write temp file, rename over target").
 *   phase "deleted"       inode unlinked.
 *
 * Every user-space read checks with fstat() that the file we opened is the
 * same (dev, inode) the kernel reported, so a path that now points to a
 * different file is reported as "inode_mismatch" instead of a wrong hash.
 * Files are opened through /proc/<pid>/root when possible so paths resolve in
 * the agent's mount namespace (containers), and with O_NOATIME so the observer
 * does not change the files it observes.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif

#define CONTENT_TABLE_SIZE 32768 /* power of two */
#define CONTENT_READ_MAX_BYTES (4LL * 1024 * 1024)
#define CONTENT_DEBOUNCE_MS 500
#define CONTENT_FLUSH_EVERY_MS 100
#define CONTENT_READ_CHUNK (256 * 1024)
#define CONTENT_IMA_ALGO_SHA256 4 /* enum hash_algo in include/uapi/linux/hash_info.h */

/* ------------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4). Small and dependency-free so the loader keeps its  */
/* existing link line; the kernel side uses the kernel's own SHA-256 via IMA. */

struct content_sha256 {
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t buf[64];
	size_t buflen;
};

static const uint32_t content_sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define CONTENT_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void content_sha256_block(struct content_sha256 *ctx, const uint8_t *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
		       (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = CONTENT_ROTR(w[i - 15], 7) ^ CONTENT_ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = CONTENT_ROTR(w[i - 2], 17) ^ CONTENT_ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
	for (i = 0; i < 64; i++) {
		uint32_t s1 = CONTENT_ROTR(e, 6) ^ CONTENT_ROTR(e, 11) ^ CONTENT_ROTR(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + s1 + ch + content_sha256_k[i] + w[i];
		uint32_t s0 = CONTENT_ROTR(a, 2) ^ CONTENT_ROTR(a, 13) ^ CONTENT_ROTR(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = s0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static inline void content_sha256_init(struct content_sha256 *ctx)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	memcpy(ctx->state, iv, sizeof(iv));
	ctx->bitlen = 0;
	ctx->buflen = 0;
}

static inline void content_sha256_update(struct content_sha256 *ctx, const uint8_t *data, size_t len)
{
	ctx->bitlen += (uint64_t)len * 8;
	if (ctx->buflen) {
		size_t take = 64 - ctx->buflen < len ? 64 - ctx->buflen : len;
		memcpy(ctx->buf + ctx->buflen, data, take);
		ctx->buflen += take;
		data += take;
		len -= take;
		if (ctx->buflen == 64) {
			content_sha256_block(ctx, ctx->buf);
			ctx->buflen = 0;
		}
	}
	while (len >= 64) {
		content_sha256_block(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len) {
		memcpy(ctx->buf, data, len);
		ctx->buflen = len;
	}
}

static inline void content_sha256_final(struct content_sha256 *ctx, uint8_t out[32])
{
	uint64_t bitlen = ctx->bitlen;
	uint8_t pad = 0x80;
	uint8_t zero = 0;
	uint8_t lenbuf[8];
	int i;

	content_sha256_update(ctx, &pad, 1);
	while (ctx->buflen != 56)
		content_sha256_update(ctx, &zero, 1);
	for (i = 0; i < 8; i++)
		lenbuf[i] = (uint8_t)(bitlen >> (56 - 8 * i));
	/* Append the length without counting it in bitlen. */
	memcpy(ctx->buf + 56, lenbuf, 8);
	content_sha256_block(ctx, ctx->buf);
	ctx->buflen = 0;
	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		out[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}

static inline void content_hex(const uint8_t *digest, int len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < len; i++) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 15];
	}
	out[len * 2] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Hashing a file from user space.                                           */

enum content_us_status {
	CONTENT_US_OK = 0,
	CONTENT_US_PATH_GONE,      /* no file at the path any more */
	CONTENT_US_INODE_MISMATCH, /* the path now names a different file */
	CONTENT_US_TOO_LARGE,
	CONTENT_US_UNKNOWN_PATH,   /* we never learned a path for the inode */
	CONTENT_US_ERROR,
};

static inline const char *content_us_status_name(int status)
{
	switch (status) {
	case CONTENT_US_OK: return "ok";
	case CONTENT_US_PATH_GONE: return "path_gone";
	case CONTENT_US_INODE_MISMATCH: return "inode_mismatch";
	case CONTENT_US_TOO_LARGE: return "too_large";
	case CONTENT_US_UNKNOWN_PATH: return "unknown_path";
	default: return "error";
	}
}

/* Kernel s_dev is MAJOR << 20 | MINOR; stat() returns the user-space dev_t. */
static inline dev_t content_kernel_dev_to_user(uint32_t kdev)
{
	return makedev(kdev >> 20, kdev & 0xfffff);
}

static inline int content_open_verified(pid_t pid, const char *path, uint32_t kdev, uint64_t ino,
				 struct stat *st, int *err_out)
{
	const int flags = O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW;
	char ns_path[MAX_FILE_PATH_LEN + 32];
	bool mismatch = false;
	int attempts = 0;
	int last_err = ENOENT;

	/* Try the agent's mount namespace first, then the host path. */
	for (int i = 0; i < 2; i++) {
		const char *candidate = path;
		int fd;

		if (i == 0) {
			if (pid <= 0)
				continue;
			snprintf(ns_path, sizeof(ns_path), "/proc/%d/root%s", pid, path);
			candidate = ns_path;
		}
		attempts++;
		fd = open(candidate, flags | O_NOATIME);
		if (fd < 0 && errno == EPERM)
			fd = open(candidate, flags);  /* O_NOATIME needs ownership or CAP_FOWNER */
		if (fd < 0) {
			last_err = errno;
			continue;
		}
		if (fstat(fd, st) == 0 && S_ISREG(st->st_mode) && st->st_ino == ino &&
		    st->st_dev == content_kernel_dev_to_user(kdev))
			return fd;
		mismatch = true;
		close(fd);
	}
	*err_out = mismatch ? 0 : last_err;
	if (mismatch)
		return -CONTENT_US_INODE_MISMATCH;
	return (attempts && (last_err == ENOENT || last_err == ENOTDIR))
		? -CONTENT_US_PATH_GONE : -CONTENT_US_ERROR;
}

static inline int content_hash_file(pid_t pid, const char *path, uint32_t kdev, uint64_t ino,
			     long long max_bytes, char hex_out[65], struct stat *st_out,
			     int *err_out)
{
	struct content_sha256 ctx;
	uint8_t digest[32];
	uint8_t *buf;
	long long total = 0;
	ssize_t n;
	int fd;

	*err_out = 0;
	if (!path || path[0] != '/')
		return CONTENT_US_UNKNOWN_PATH;
	fd = content_open_verified(pid, path, kdev, ino, st_out, err_out);
	if (fd < 0)
		return -fd;
	if (st_out->st_size > max_bytes) {
		close(fd);
		return CONTENT_US_TOO_LARGE;
	}
	buf = malloc(CONTENT_READ_CHUNK);
	if (!buf) {
		close(fd);
		*err_out = ENOMEM;
		return CONTENT_US_ERROR;
	}
	content_sha256_init(&ctx);
	while ((n = read(fd, buf, CONTENT_READ_CHUNK)) != 0) {
		if (n < 0) {
			if (errno == EINTR)
				continue;
			*err_out = errno;
			free(buf);
			close(fd);
			return CONTENT_US_ERROR;
		}
		total += n;
		if (total > max_bytes) {  /* grew while we were reading */
			free(buf);
			close(fd);
			return CONTENT_US_TOO_LARGE;
		}
		content_sha256_update(&ctx, buf, (size_t)n);
	}
	free(buf);
	close(fd);
	content_sha256_final(&ctx, digest);
	content_hex(digest, 32, hex_out);
	return CONTENT_US_OK;
}

/* ------------------------------------------------------------------------ */
/* Per-inode bookkeeping.                                                    */

struct content_entry {
	bool used;
	uint32_t dev;
	uint64_t ino;
	char *path;             /* latest known path */
	bool read_hashed;       /* "read" emitted */
	bool pre_hashed;        /* "before_write" emitted */
	bool deleted;           /* last link gone (or replaced by a rename) */
	bool dirty;             /* released after a write; "after_write" pending */
	uint64_t dirty_since_ms;
	pid_t last_pid;
	char last_comm[TASK_COMM_LEN];
	bool have_after;        /* last "after_write" stat, to skip unchanged files */
	struct timespec after_mtime;
	struct timespec after_ctime;
	off_t after_size;
};

static struct content_entry content_table[CONTENT_TABLE_SIZE];
static int content_used_count;
static int content_dirty_count;
static bool content_enabled;
static long long content_max_bytes = 16LL * 1024 * 1024;
/* Read-only files are hashed inside the ring buffer callback; keep each read
 * short so the consumer does not fall behind the kernel. */
static long long content_read_max_bytes = CONTENT_READ_MAX_BYTES;
static int content_scope_fd = -1;
static uint64_t content_last_flush_ms;

static inline uint64_t content_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static inline uint64_t content_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline struct content_entry *content_slot(uint32_t dev, uint64_t ino, bool create)
{
	uint64_t h = (ino * 0x9E3779B97F4A7C15ULL) ^ ((uint64_t)dev * 0xC2B2AE3D27D4EB4FULL);

	for (int i = 0; i < CONTENT_TABLE_SIZE; i++) {
		struct content_entry *entry = &content_table[(h + i) & (CONTENT_TABLE_SIZE - 1)];
		if (entry->used) {
			if (entry->dev == dev && entry->ino == ino)
				return entry;
			continue;
		}
		if (!create)
			return NULL;
		memset(entry, 0, sizeof(*entry));
		entry->used = true;
		entry->dev = dev;
		entry->ino = ino;
		content_used_count++;
		return entry;
	}
	return NULL;
}

/* When the table gets full, forget files that were only read: written,
 * renamed and dirty inodes are the ones later events must be paired with.
 * Open addressing has no cheap delete, so rebuild the table. */
static inline void content_compact(void)
{
	struct content_entry *keep = calloc(CONTENT_TABLE_SIZE, sizeof(*keep));
	int kept = 0;

	if (!keep)
		return;
	for (int i = 0; i < CONTENT_TABLE_SIZE; i++) {
		struct content_entry *entry = &content_table[i];
		if (!entry->used)
			continue;
		if (entry->dirty || (entry->pre_hashed && !entry->deleted))
			keep[kept++] = *entry;
		else
			free(entry->path);
	}
	memset(content_table, 0, sizeof(content_table));
	content_used_count = 0;
	for (int i = 0; i < kept; i++) {
		struct content_entry *slot = content_slot(keep[i].dev, keep[i].ino, true);
		if (slot)
			*slot = keep[i];
	}
	free(keep);
}

static inline struct content_entry *content_lookup(uint32_t dev, uint64_t ino, bool create)
{
	struct content_entry *entry = content_slot(dev, ino, false);

	if (entry || !create)
		return entry;
	if (content_used_count >= CONTENT_TABLE_SIZE * 3 / 4)
		content_compact();
	return content_slot(dev, ino, true);  /* NULL only if all entries are pinned */
}

/* The inode number is reused for a new file: start its bookkeeping over. */
static inline void content_new_life(struct content_entry *entry)
{
	if (entry->dirty)
		content_dirty_count--;
	entry->read_hashed = false;
	entry->pre_hashed = false;
	entry->deleted = false;
	entry->dirty = false;
	entry->have_after = false;
}

static inline void content_set_path(struct content_entry *entry, const char *path)
{
	if (!entry || !path || !path[0])
		return;
	if (entry->path && strcmp(entry->path, path) == 0)
		return;
	free(entry->path);
	entry->path = strdup(path);
}

static inline void content_mark_dirty(struct content_entry *entry, pid_t pid, const char *comm)
{
	if (!entry->dirty)
		content_dirty_count++;
	entry->dirty = true;
	entry->dirty_since_ms = content_now_ms();
	entry->last_pid = pid;
	memcpy(entry->last_comm, comm, sizeof(entry->last_comm));
}

static inline bool content_pid_in_scope(pid_t pid)
{
	uint32_t key = (uint32_t)pid;
	uint8_t value;

	if (content_scope_fd < 0 || pid <= 0)
		return false;
	return bpf_map_lookup_elem(content_scope_fd, &key, &value) == 0;
}

static inline void content_scope_add(pid_t pid)
{
	uint32_t key = (uint32_t)pid;
	uint8_t one = 1;

	if (content_scope_fd >= 0 && pid > 0)
		bpf_map_update_elem(content_scope_fd, &key, &one, BPF_ANY);
}

static inline void content_scope_remove(pid_t pid)
{
	uint32_t key = (uint32_t)pid;

	if (content_scope_fd >= 0 && pid > 0)
		bpf_map_delete_elem(content_scope_fd, &key);
}

/* ------------------------------------------------------------------------ */
/* Output: one FILE_CONTENT JSON line per phase.                            */

struct content_record {
	uint64_t timestamp_ns;
	pid_t pid;
	const char *comm;
	const char *phase;
	const char *path;
	uint32_t dev;
	uint64_t ino;
	long long size;            /* < 0: unknown */
	const char *sha256;        /* NULL: no hash */
	const char *hash_source;   /* kernel_ima, userspace, userspace_late */
	const char *hash_status;
	int error;                 /* errno or -errno, 0 if none */
	const char *renamed_from;
	uint64_t replaced_ino;
	bool exchange;
	int remaining_links;       /* deleted: links left, -1 if not applicable */
};

static inline void content_print(const struct content_record *r)
{
	char comm_esc[TASK_COMM_LEN * 2 + 1];
	char path_esc[MAX_FILE_PATH_LEN * 6 + 1];

	json_escape(r->comm ? r->comm : "", comm_esc, sizeof(comm_esc));
	printf("{\"timestamp\":%llu,\"event\":\"FILE_CONTENT\",\"comm\":\"%s\",\"pid\":%d,"
	       "\"phase\":\"%s\"",
	       (unsigned long long)r->timestamp_ns, comm_esc, r->pid, r->phase);
	if (r->path && r->path[0]) {
		json_escape(r->path, path_esc, sizeof(path_esc));
		printf(",\"filepath\":\"%s\"", path_esc);
	}
	printf(",\"dev\":%u,\"dev_maj_min\":\"%u:%u\",\"ino\":%llu",
	       r->dev, r->dev >> 20, r->dev & 0xfffff, (unsigned long long)r->ino);
	if (r->size >= 0)
		printf(",\"size\":%lld", r->size);
	if (r->sha256)
		printf(",\"sha256\":\"%s\"", r->sha256);
	if (r->hash_source)
		printf(",\"hash_source\":\"%s\"", r->hash_source);
	if (r->hash_status)
		printf(",\"hash_status\":\"%s\"", r->hash_status);
	if (r->error)
		printf(",\"error\":%d", r->error);
	if (r->renamed_from && r->renamed_from[0]) {
		json_escape(r->renamed_from, path_esc, sizeof(path_esc));
		printf(",\"renamed_from\":\"%s\"", path_esc);
	}
	if (r->replaced_ino)
		printf(",\"replaced_ino\":%llu", (unsigned long long)r->replaced_ino);
	if (r->exchange)
		printf(",\"exchange\":true");
	if (r->remaining_links >= 0)
		printf(",\"remaining_links\":%d", r->remaining_links);
	printf("}\n");
	fflush(stdout);
}

/* Hash an inode from user space and print the result for the given phase. */
static inline int content_userspace_record(struct content_entry *entry, uint64_t ts_ns, pid_t pid,
					   const char *comm, const char *phase,
					   const char *source, long long max_bytes,
					   struct stat *st_out)
{
	char hex[65];
	struct stat st = {};
	int err = 0;
	int status = content_hash_file(pid, entry->path, entry->dev, entry->ino,
				       max_bytes, hex, &st, &err);
	struct content_record r = {
		.timestamp_ns = ts_ns,
		.pid = pid,
		.comm = comm,
		.phase = phase,
		.path = entry->path,
		.dev = entry->dev,
		.ino = entry->ino,
		.size = status == CONTENT_US_OK || status == CONTENT_US_TOO_LARGE ? (long long)st.st_size : -1,
		.sha256 = status == CONTENT_US_OK ? hex : NULL,
		.hash_source = source,
		.hash_status = content_us_status_name(status),
		.error = err,
		.remaining_links = -1,
	};
	content_print(&r);
	if (st_out)
		*st_out = st;
	return status;
}

/* ------------------------------------------------------------------------ */
/* Event handlers called from process.c.                                    */

/* Existing FILE_OPEN event (already reported). Hash first read-only opens. */
static inline void content_on_file_open(const struct event *e)
{
	struct content_entry *entry;
	unsigned char access = e->file_op.access;

	if (!content_enabled || !e->file_op.resolved || e->file_op.layer)
		return;
	if (!e->file_op.filepath[0] || e->file_op.path_error)
		return;
	if (!content_pid_in_scope(e->pid))
		return;
	entry = content_lookup(e->file_op.dev, e->file_op.ino, true);
	if (!entry)
		return;
	if (entry->deleted)
		content_new_life(entry);  /* inode number reused by a new file */
	content_set_path(entry, e->file_op.filepath);
	if (!(access & FILE_ACCESS_READ) || (access & (FILE_ACCESS_WRITE | FILE_ACCESS_EXEC)))
		return;  /* writable opens are measured in the kernel */
	if (entry->read_hashed || entry->pre_hashed)
		return;  /* we already know the content before any modification */
	if (strncmp(entry->path, "/proc/", 6) == 0 || strncmp(entry->path, "/sys/", 5) == 0 ||
	    strncmp(entry->path, "/dev/", 5) == 0)
		return;
	entry->read_hashed = true;
	content_userspace_record(entry, e->timestamp_ns, e->pid, e->comm, "read", "userspace",
				 content_read_max_bytes < content_max_bytes ? content_read_max_bytes
									    : content_max_bytes,
				 NULL);
}

static inline void content_on_kernel_event(const struct event *e)
{
	struct content_entry *entry = content_lookup(e->content.dev, e->content.ino, true);
	struct content_record r = {
		.timestamp_ns = e->timestamp_ns,
		.pid = e->pid,
		.comm = e->comm,
		.path = e->content.filepath,
		.dev = e->content.dev,
		.ino = e->content.ino,
		.size = e->content.size,
		.remaining_links = -1,
	};
	char hex[CONTENT_HASH_MAX * 2 + 1];
	char *old_path = NULL;
	bool late_fallback = false;

	switch (e->content.kind) {
	case CONTENT_KIND_PRE_WRITE:
		if (entry) {
			if (entry->deleted || e->content.hash_status == CONTENT_HASH_CREATED)
				content_new_life(entry);
			content_set_path(entry, e->content.filepath);
			entry->pre_hashed = true;
		}
		r.phase = "before_write";
		r.hash_source = "kernel_ima";
		switch (e->content.hash_status) {
		case CONTENT_HASH_OK:
			if (e->content.hash_algo != CONTENT_IMA_ALGO_SHA256) {
				/* Comparable only with the same algorithm; report the digest
				 * but do not label it sha256. */
				r.hash_status = "non_sha256_algo";
				r.error = e->content.hash_algo;
				break;
			}
			content_hex(e->content.hash, 32, hex);
			r.sha256 = hex;
			r.hash_status = "ok";
			break;
		case CONTENT_HASH_CREATED:
			r.hash_status = "created";
			break;
		case CONTENT_HASH_TOO_LARGE:
			r.hash_status = "too_large";
			break;
		case CONTENT_HASH_RDWR:
			r.hash_status = "rdwr";
			late_fallback = true;
			break;
		default:
			r.hash_status = "kernel_error";
			r.error = e->content.hash_algo;
			late_fallback = true;
			break;
		}
		content_print(&r);
		/* The kernel could not measure this open. Without O_TRUNC nothing has
		 * changed the file yet unless the agent writes in the few ms before we
		 * read it, so a user-space hash is a usable, clearly labelled
		 * fallback. With O_TRUNC the old content is gone by now. */
		if (late_fallback && entry && !(e->content.flags & O_TRUNC))
			content_userspace_record(entry, e->timestamp_ns, e->pid, e->comm,
						 "before_write", "userspace_late",
						 content_max_bytes, NULL);
		return;

	case CONTENT_KIND_WRITE_CLOSE:
		if (entry && !entry->deleted)
			content_mark_dirty(entry, e->pid, e->comm);
		return;

	case CONTENT_KIND_RENAME: {
		bool exchange = e->content.flags & 2; /* RENAME_EXCHANGE */

		r.phase = "renamed";
		r.replaced_ino = e->content.replaced_ino;
		r.exchange = exchange;
		r.error = e->content.path_error;
		if (entry) {
			if (entry->path)
				old_path = strdup(entry->path);
			content_set_path(entry, e->content.filepath);
			entry->deleted = false;
			/* Measure the content now visible at the new path. */
			content_mark_dirty(entry, e->pid, e->comm);
		}
		r.renamed_from = old_path;
		content_print(&r);
		if (e->content.replaced_ino) {
			struct content_entry *victim = content_lookup(e->content.dev,
								      e->content.replaced_ino, false);
			if (victim && exchange) {
				content_set_path(victim, old_path);  /* the two swapped places */
			} else if (victim) {
				if (victim->dirty)
					content_dirty_count--;
				victim->dirty = false;
				victim->deleted = true;
			}
		}
		free(old_path);
		return;
	}

	case CONTENT_KIND_UNLINK:
		r.phase = e->content.nlink > 1 ? "link_removed" : "deleted";
		r.remaining_links = e->content.nlink > 0 ? (int)e->content.nlink - 1 : 0;
		r.error = e->content.path_error;
		if (entry && e->content.nlink <= 1) {
			if (entry->dirty)
				content_dirty_count--;
			entry->dirty = false;
			entry->deleted = true;
		}
		if (entry && !r.path[0])
			r.path = entry->path;
		content_print(&r);
		return;
	}
}

/* Hash inodes whose last release is older than the debounce window. */
static inline void content_flush_dirty(bool force)
{
	uint64_t now = content_now_ms();

	if (!content_enabled || content_dirty_count <= 0)
		return;
	if (!force && now - content_last_flush_ms < CONTENT_FLUSH_EVERY_MS)
		return;
	content_last_flush_ms = now;

	for (int i = 0; i < CONTENT_TABLE_SIZE && content_dirty_count > 0; i++) {
		struct content_entry *entry = &content_table[i];
		struct stat st;

		if (!entry->used || !entry->dirty)
			continue;
		if (!force && now - entry->dirty_since_ms < CONTENT_DEBOUNCE_MS)
			continue;
		entry->dirty = false;
		content_dirty_count--;

		/* Skip the re-read when size and timestamps are unchanged since the
		 * last after_write hash (e.g. a log reopened and closed unwritten). */
		if (entry->have_after && entry->path && stat(entry->path, &st) == 0 &&
		    st.st_ino == entry->ino && st.st_size == entry->after_size &&
		    st.st_mtim.tv_sec == entry->after_mtime.tv_sec &&
		    st.st_mtim.tv_nsec == entry->after_mtime.tv_nsec &&
		    st.st_ctim.tv_sec == entry->after_ctime.tv_sec &&
		    st.st_ctim.tv_nsec == entry->after_ctime.tv_nsec)
			continue;

		if (content_userspace_record(entry, content_now_ns(), entry->last_pid,
					     entry->last_comm, "after_write", "userspace",
					     content_max_bytes, &st) == CONTENT_US_OK) {
			entry->have_after = true;
			entry->after_size = st.st_size;
			entry->after_mtime = st.st_mtim;
			entry->after_ctime = st.st_ctim;
		}
	}
}

#endif /* __PROCESS_EXT_CONTENT_H */
