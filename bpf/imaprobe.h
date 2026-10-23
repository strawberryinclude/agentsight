/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * imaprobe: feasibility probe for in-kernel content hashing.
 * Shared between imaprobe.bpf.c (kernel side) and imaprobe.c (user side).
 */
#ifndef __IMAPROBE_H
#define __IMAPROBE_H

#define IMAPROBE_COMM_LEN 16
#define IMAPROBE_MAX_COMMS 2
#define IMAPROBE_PATH_LEN 256
#define IMAPROBE_HASH_LEN 64 /* large enough for SHA-512 */

#define IMAPROBE_KIND_OPEN    1
#define IMAPROBE_KIND_RELEASE 2

struct imaprobe_event {
	int kind;                 /* IMAPROBE_KIND_* */
	int pid;
	unsigned int f_mode;      /* FMODE_READ = 1, FMODE_WRITE = 2 */
	int path_len;             /* bpf_d_path() return value */
	long long algo;           /* bpf_ima_file_hash() return: algo id or -errno */
	long long size;           /* inode size when the hook ran */
	unsigned long long ino;
	char comm[IMAPROBE_COMM_LEN];
	char path[IMAPROBE_PATH_LEN];
	unsigned char hash[IMAPROBE_HASH_LEN];
};

#endif /* __IMAPROBE_H */
