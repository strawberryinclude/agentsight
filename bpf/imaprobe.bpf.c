// SPDX-License-Identifier: GPL-2.0
/*
 * imaprobe: does bpf_ima_file_hash() work on this kernel, and at which hooks?
 *
 * lsm.s/file_open    runs after path resolution, before the caller gets the fd
 *                    (and before O_TRUNC truncation), so the hash it computes is
 *                    the content as it was before this opener could touch it.
 * lsm.s/file_release runs when the last reference to the open file goes away,
 *                    i.e. after the last write through it. Only exists on newer
 *                    kernels and may not be allowed as a sleepable hook; the
 *                    loader retries without it if loading fails.
 *
 * "lsm.s" = sleepable BPF LSM program. bpf_ima_file_hash() reads the file, which
 * can sleep, so it is only allowed from sleepable LSM hooks.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "imaprobe.h"

char LICENSE[] SEC("license") = "GPL";

#define S_IFMT  00170000
#define S_IFREG 0100000

/* Filled in by the loader before load: which command names to watch. */
const volatile char target_comms[IMAPROBE_MAX_COMMS][IMAPROBE_COMM_LEN] = {};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline bool comm_equal(const char *comm, int idx)
{
	for (int i = 0; i < IMAPROBE_COMM_LEN; i++) {
		if (comm[i] != target_comms[idx][i])
			return false;
		if (comm[i] == '\0')
			return true;
	}
	return true;
}

static __always_inline bool is_target(void)
{
	char comm[IMAPROBE_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));
	for (int j = 0; j < IMAPROBE_MAX_COMMS; j++) {
		if (target_comms[j][0] && comm_equal(comm, j))
			return true;
	}
	return false;
}

static __always_inline void emit(struct file *file, int kind)
{
	struct imaprobe_event *e;
	struct inode *inode = file->f_inode;

	/* Cheap filters first: hashing is the expensive part. */
	if ((inode->i_mode & S_IFMT) != S_IFREG)
		return;
	if (!is_target())
		return;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->f_mode = file->f_mode;
	e->ino = inode->i_ino;
	e->size = inode->i_size;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->path_len = bpf_d_path(&file->f_path, e->path, sizeof(e->path));
	e->algo = bpf_ima_file_hash(file, e->hash, sizeof(e->hash));
	bpf_ringbuf_submit(e, 0);
}

SEC("lsm.s/file_open")
int BPF_PROG(probe_file_open, struct file *file)
{
	emit(file, IMAPROBE_KIND_OPEN);
	return 0; /* never deny the open: we only observe */
}

SEC("lsm.s/file_release")
int BPF_PROG(probe_file_release, struct file *file)
{
	emit(file, IMAPROBE_KIND_RELEASE);
	return 0;
}
