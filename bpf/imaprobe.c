// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * imaprobe loader. Usage: sudo ./imaprobe [comm1] [comm2]
 * Default comms: cat tee. Prints one line per open/release of a regular file
 * by those commands, with the in-kernel SHA-256 of the file content.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "imaprobe.h"
#include "imaprobe.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

/* Values of enum hash_algo in include/uapi/linux/hash_info.h */
static int digest_len(long long algo)
{
	switch (algo) {
	case 2: return 20; /* sha1 */
	case 4: return 32; /* sha256 */
	case 5: return 48; /* sha384 */
	case 6: return 64; /* sha512 */
	default: return 0;
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct imaprobe_event *e = data;
	int i, n;

	(void)ctx;
	if (size < sizeof(*e))
		return 0;
	printf("%-7s pid=%-6d comm=%-8s mode=%c%c ino=%llu size=%lld path=%s\n",
	       e->kind == IMAPROBE_KIND_OPEN ? "OPEN" : "RELEASE",
	       e->pid, e->comm,
	       (e->f_mode & 1) ? 'r' : '-', (e->f_mode & 2) ? 'w' : '-',
	       e->ino, e->size, e->path_len > 0 ? e->path : "?");
	if (e->algo < 0) {
		printf("        hash: error %lld (%s)\n", e->algo, strerror((int)-e->algo));
	} else {
		n = digest_len(e->algo);
		printf("        hash: ");
		for (i = 0; i < n; i++)
			printf("%02x", e->hash[i]);
		printf("  (algo %lld)\n", e->algo);
	}
	fflush(stdout);
	return 0;
}

static struct imaprobe_bpf *open_skel(int argc, char **argv)
{
	struct imaprobe_bpf *skel = imaprobe_bpf__open();
	const char *defaults[IMAPROBE_MAX_COMMS] = { "cat", "tee" };

	if (!skel)
		return NULL;
	for (int i = 0; i < IMAPROBE_MAX_COMMS; i++) {
		const char *c = (argc > 1) ? (i + 1 < argc ? argv[i + 1] : "") : defaults[i];
		strncpy((char *)skel->rodata->target_comms[i], c, IMAPROBE_COMM_LEN - 1);
	}
	return skel;
}

int main(int argc, char **argv)
{
	struct imaprobe_bpf *skel;
	struct ring_buffer *rb = NULL;
	bool with_release = true;
	int err;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	skel = open_skel(argc, argv);
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	err = imaprobe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "\n>>> load with lsm.s/file_release failed (%d); retrying with file_open only\n\n", err);
		imaprobe_bpf__destroy(skel);
		skel = open_skel(argc, argv);
		if (!skel)
			return 1;
		bpf_program__set_autoload(skel->progs.probe_file_release, false);
		with_release = false;
		err = imaprobe_bpf__load(skel);
		if (err) {
			fprintf(stderr, "failed to load BPF programs: %d\n", err);
			goto out;
		}
	}
	err = imaprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto out;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "failed to create ring buffer: %d\n", err);
		goto out;
	}

	printf("imaprobe: watching comm='%s' '%s'  file_release hook: %s\n",
	       skel->rodata->target_comms[0], skel->rodata->target_comms[1],
	       with_release ? "yes" : "NO");
	printf("Ctrl+C to stop.\n");
	fflush(stdout);

	while (!stop) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "ring buffer poll error: %d\n", err);
			break;
		}
	}
	err = 0;
out:
	ring_buffer__free(rb);
	imaprobe_bpf__destroy(skel);
	return err ? 1 : 0;
}
