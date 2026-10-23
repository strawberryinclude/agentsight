/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PROCESS_H
#define __PROCESS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_FILE_PATH_LEN 4096
#define MAX_COMMAND_FILTERS 10
#define MAX_TRACKED_PIDS 4096
#define MAX_COMMAND_LEN 256

enum filter_mode {
	FILTER_MODE_ALL = 0,      /* Trace all processes and all read/write operations */
	FILTER_MODE_PROC = 1,     /* Trace all processes but only read/write for tracked PIDs */
	FILTER_MODE_FILTER = 2,   /* Only trace processes matching filters and their read/write */
};

enum event_type {
	EVENT_TYPE_PROCESS = 0,
	EVENT_TYPE_BASH_READLINE = 1,
	EVENT_TYPE_FILE_OPERATION = 2,
	EVENT_TYPE_FILE_CONTENT = 3,  /* content-hash lifecycle, see process_ext/bpf_content.h */
};

/* Large enough for any IMA digest (SHA-512). SHA-256 uses the first 32 bytes. */
#define CONTENT_HASH_MAX 64

/* What happened to the file. One kernel event per kind. */
enum content_kind {
	CONTENT_KIND_PRE_WRITE = 1,   /* first writable open: content before modification */
	CONTENT_KIND_WRITE_CLOSE = 2, /* a writable fd was closed: content may have changed */
	CONTENT_KIND_RENAME = 3,      /* inode moved to a new path (atomic replace) */
	CONTENT_KIND_UNLINK = 4,      /* inode unlinked */
};

/* Outcome of the in-kernel hash for CONTENT_KIND_PRE_WRITE. */
enum content_hash_status {
	CONTENT_HASH_NONE = 0,      /* not hashed in the kernel for this kind */
	CONTENT_HASH_OK = 1,        /* hash[] holds the digest, hash_algo the IMA algo id */
	CONTENT_HASH_CREATED = 2,   /* open created the file: there is no prior content */
	CONTENT_HASH_TOO_LARGE = 3, /* skipped: larger than the configured limit */
	CONTENT_HASH_ERROR = 4,     /* bpf_ima_file_hash failed, hash_algo holds -errno */
	CONTENT_HASH_RDWR = 5,      /* O_RDWR open: IMA cannot read it at this hook */
};

struct event {
	enum event_type type;
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	unsigned long long timestamp_ns;
	char comm[TASK_COMM_LEN];
	char full_command[MAX_COMMAND_LEN];     /* full command line with args */
	union {
		char filename[MAX_FILENAME_LEN];     /* for process events */
		char command[MAX_COMMAND_LEN];       /* for bash readline events */
		struct {                             /* for file operation events */
			char filepath[MAX_FILE_PATH_LEN];
			int fd;
			int flags;
			bool is_open;  /* true for open/openat, false for close */
			bool resolved; /* security_file_open, not a syscall entry */
			bool layer;
			unsigned char access; /* FILE_ACCESS_* */
			int path_error;
			unsigned int dev;
			unsigned long long ino;
		} file_op;
		struct {                             /* for file content events */
			char filepath[MAX_FILE_PATH_LEN]; /* empty for WRITE_CLOSE */
			unsigned long long ino;
			unsigned long long replaced_ino; /* RENAME: inode it replaced, 0 if none */
			long long size;                  /* i_size when the hook ran */
			unsigned int dev;                /* kernel s_dev (MAJOR << 20 | MINOR) */
			int kind;                        /* enum content_kind */
			int hash_status;                 /* enum content_hash_status */
			int hash_algo;                   /* IMA enum hash_algo, or -errno */
			int flags;                       /* f_flags or rename flags */
			int path_error;
			unsigned int nlink;              /* UNLINK: links before the unlink */
			unsigned char hash[CONTENT_HASH_MAX];
		} content;
	};
	bool exit_event;
};

#define FILE_ACCESS_READ  1
#define FILE_ACCESS_WRITE 2
#define FILE_ACCESS_EXEC  4

struct command_filter {
	char comm[TASK_COMM_LEN];
};

struct pid_info {
	pid_t pid;
	pid_t ppid;
	bool is_tracked;
};

#endif /* __PROCESS_H */
