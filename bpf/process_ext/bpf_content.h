/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_EXT_BPF_CONTENT_H
#define __PROCESS_EXT_BPF_CONTENT_H

/*
 * File content hashing at the kernel boundary.
 *
 * Goal: for every regular file the agent touches, record the hash of the
 * content before the agent modified it and the hash of the content after its
 * last write, without instrumenting the agent.
 *
 * Four hooks, all scoped to the agent's process tree:
 *
 *  lsm.s/file_open     First writable open of an inode in this session. The
 *                      LSM hook runs after path resolution but before the
 *                      opener receives the fd and before O_TRUNC truncation,
 *                      so bpf_ima_file_hash() sees the pre-modification
 *                      content. This is the only point where nothing the agent
 *                      does can race with the measurement.
 *
 *                      At this hook the file is not fully open yet:
 *                      FMODE_CAN_READ is set later in do_dentry_open(), and
 *                      IMA's read path requires it. IMA only works around this
 *                      when the file lacks FMODE_READ (O_WRONLY): it then opens
 *                      a private, fully opened read-only instance. So:
 *                        O_WRONLY  hashed here, exactly            (the common
 *                                  case: editors, agents, shells use "w"/"a")
 *                        O_RDWR    cannot be hashed here; reported as
 *                                  CONTENT_HASH_RDWR, user space falls back
 *                        O_RDONLY  not hashed here; user space hashes it from
 *                                  the existing FILE_OPEN event
 *                      IMA's private open re-enters security_file_open; the
 *                      in-flight map below lets this program and the existing
 *                      fexit/security_file_open tracer ignore it.
 *
 *  lsm/file_free_security
 *                      The last reference to a writable open file of a
 *                      pre-hashed inode was dropped: close(2), process exit,
 *                      munmap of a shared mapping, or a dup'd fd all funnel into
 *                      this single hook in __fput(), so no write through that
 *                      file can follow. The kernel only reports it; user space
 *                      hashes the final content after a short debounce. Hashing
 *                      here in the kernel is not possible: the hook cannot
 *                      sleep, and neither can file_release (added in 6.9; not
 *                      in the sleepable set as of 6.12), so a newer kernel does
 *                      not change this. Hooking filp_flush()/filp_close() instead
 *                      would be fragile: filp_flush() is small and may be
 *                      inlined into close(2), so an fentry probe can miss it.
 *
 *  lsm.s/path_rename   Atomic replace (write temp file, rename over target):
 *                      reports which inode now lives at which path and which
 *                      inode it replaced.
 *
 *  lsm.s/path_unlink   The inode was deleted, so it has no "after" content.
 *
 *  tp_btf/sched_process_fork
 *                      Scope inheritance. A child of an in-scope process is in
 *                      scope from the moment it is created, before it runs.
 *                      Without this, a child that leaves the session (agents
 *                      run tool commands with setsid(), e.g. Claude Code's Bash
 *                      tool) depends on user space adding its pid after the
 *                      exec event, and a short command (rm) is done by then.
 *
 * Overhead: every hook returns after a few field loads unless the file is a
 * regular file opened by an in-scope process. Each inode is hashed in the
 * kernel at most once per session (content_seen), and files above
 * content_hash_max_bytes are skipped.
 */

#define FMODE_CREATED 0x100000
#define NAME_MAX_LEN 255
#define RENAME_EXCHANGE 2

/* content_seen values */
#define CONTENT_SEEN_HASHED 1 /* measured before its first write */
#define CONTENT_SEEN_TRACK 2  /* not measured (e.g. renamed in), pair releases only */

/* Pseudo filesystems whose "files" are not content the agent edits. */
#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define CGROUP2_SUPER_MAGIC 0x63677270
#define DEBUGFS_MAGIC 0x64626720
#define TRACEFS_MAGIC 0x74726163
#define SECURITYFS_MAGIC 0x73636673
#define BPF_FS_MAGIC 0xcafe4a11
#define DEVPTS_SUPER_MAGIC 0x1cd1
#define ANON_INODE_FS_MAGIC 0x09041934

const volatile bool trace_content = false;
/* Session id of the traced command; 0 = rely on content_scope_pids only. */
const volatile unsigned int content_target_session = 0;
const volatile long long content_hash_max_bytes = 16LL * 1024 * 1024;

struct content_inode_key {
	u64 ino;
	u32 dev;
	u32 pad;
};

/* Inodes the agent wrote or renamed in this session. An entry is removed when
 * the inode's last link goes away, so a reused inode number starts fresh. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct content_inode_key);
	__type(value, u8);
} content_seen SEC(".maps");

/* Thread is inside bpf_ima_file_hash(). IMA opens a private read-only file
 * instance, which re-enters security_file_open(): our file_open program (BPF
 * LSM programs have no recursion protection) and the existing
 * fexit/security_file_open tracer both skip it, so it is not reported as an
 * agent read. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} content_inflight SEC(".maps");

/* Agent process tree. Filled by user space (seeds, pid/comm filter, exec of a
 * descendant), by the kernel at fork (content_fork below, no race), and
 * emptied by user space on exit events. The session check in
 * content_in_scope() covers the traced command's own session. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_PIDS);
	__type(key, u32);
	__type(value, u8);
} content_scope_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} content_dropped SEC(".maps");

/* Set by user space after content_fork is attached in session mode. From then
 * on the scope is complete in the kernel (session, seeds, every descendant from
 * its first instruction), so the resolved file-open tracer can drop opens of
 * other processes here instead of sending them all through the ring buffer.
 * Without it, a burst of unrelated opens (AgentSight's own /proc scan touches
 * ~1000 files every 2 s) overflowed the ring and took agent events with it. */
volatile bool content_scope_complete = false;

static __always_inline void content_count_drop(void)
{
	u32 zero = 0;
	u64 *count = bpf_map_lookup_elem(&content_dropped, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static __always_inline bool content_in_scope(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return false;
	if (!is_cgroup_tracked())
		return false;
	if (bpf_map_lookup_elem(&content_scope_pids, &tgid))
		return true;
	if (content_target_session) {
		struct pid *sid = BPF_CORE_READ(task, signal, pids[PIDTYPE_SID]);
		u32 nr = BPF_CORE_READ(sid, numbers[0].nr);
		return nr == content_target_session;
	}
	return false;
}

static __always_inline bool content_regular_file(struct inode *inode)
{
	if (!inode)
		return false;
	if ((BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFREG)
		return false;
	switch (BPF_CORE_READ(inode, i_sb, s_magic)) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
	case CGROUP_SUPER_MAGIC:
	case CGROUP2_SUPER_MAGIC:
	case DEBUGFS_MAGIC:
	case TRACEFS_MAGIC:
	case SECURITYFS_MAGIC:
	case BPF_FS_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case ANON_INODE_FS_MAGIC:
	case NSFS_MAGIC:
	case PID_FS_MAGIC:
		return false;
	}
	return true;
}

static __always_inline void content_key(struct inode *inode, struct content_inode_key *key)
{
	key->ino = BPF_CORE_READ(inode, i_ino);
	key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	key->pad = 0;
}

static __always_inline struct event *content_reserve(int kind, struct inode *inode)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

	if (!e) {
		content_count_drop();
		return NULL;
	}
	e->type = EVENT_TYPE_FILE_CONTENT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	e->full_command[0] = '\0';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->content.filepath[0] = '\0';
	e->content.kind = kind;
	e->content.ino = BPF_CORE_READ(inode, i_ino);
	e->content.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	e->content.size = BPF_CORE_READ(inode, i_size);
	e->content.replaced_ino = 0;
	e->content.hash_status = CONTENT_HASH_NONE;
	e->content.hash_algo = 0;
	e->content.flags = 0;
	e->content.path_error = 0;
	e->content.nlink = 0;
	__builtin_memset(e->content.hash, 0, sizeof(e->content.hash));
	return e;
}

/* Write "<dir>/<name>" into e->content.filepath. Only valid in sleepable LSM
 * hooks, where bpf_d_path() is allowed. */
static __always_inline void content_dir_name_path(struct event *e, const struct path *dir,
						  struct dentry *dentry)
{
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	long len = bpf_d_path((struct path *)dir, e->content.filepath,
			      sizeof(e->content.filepath));
	u64 off;

	if (len < 1) {
		e->content.path_error = (int)len;
		e->content.filepath[0] = '\0';
		return;
	}
	off = (u64)len - 1; /* bpf_d_path counts the trailing NUL */
	if (off == 1 && e->content.filepath[0] == '/')
		off = 0;        /* directory is "/" */
	if (off > MAX_FILE_PATH_LEN - NAME_MAX_LEN - 2) {
		e->content.path_error = -36; /* -ENAMETOOLONG */
		return;
	}
	e->content.filepath[off] = '/';
	bpf_probe_read_kernel_str(&e->content.filepath[off + 1], NAME_MAX_LEN + 1, name);
}

SEC("lsm.s/file_open")
int BPF_PROG(content_file_open, struct file *file)
{
	struct content_inode_key key;
	unsigned char digest[CONTENT_HASH_MAX] = {};
	u64 id = bpf_get_current_pid_tgid();
	struct inode *inode;
	struct event *e;
	int status, algo = 0;
	long long size;
	long path_len;
	u8 hashed = CONTENT_SEEN_HASHED;
	u8 one = 1;
	u8 *seen;

	/* Cheapest checks first: this hook runs for every open on the system. */
	if (!trace_content)
		return 0;
	if (!(file->f_mode & FMODE_WRITE))
		return 0;  /* read-only: user space hashes it, see header comment */
	if (bpf_map_lookup_elem(&content_inflight, &id))
		return 0;  /* defensive: we are inside our own IMA call */
	inode = file->f_inode;
	if (!content_regular_file(inode) || !content_in_scope())
		return 0;

	content_key(inode, &key);
	seen = bpf_map_lookup_elem(&content_seen, &key);
	if (seen && *seen == CONTENT_SEEN_HASHED)
		return 0;  /* already measured before its first write */
	bpf_map_update_elem(&content_seen, &key, &hashed, BPF_ANY);

	size = inode->i_size;
	if (file->f_mode & FMODE_CREATED) {
		status = CONTENT_HASH_CREATED;
	} else if (file->f_mode & FMODE_READ) {
		status = CONTENT_HASH_RDWR;  /* see header comment */
	} else if (size > content_hash_max_bytes) {
		status = CONTENT_HASH_TOO_LARGE;
	} else {
		/* Hash into the stack first so no ring buffer record is held
		 * (and blocks the consumer) while IMA reads the file. */
		bpf_map_update_elem(&content_inflight, &id, &one, BPF_ANY);
		algo = bpf_ima_file_hash(file, digest, sizeof(digest));
		bpf_map_delete_elem(&content_inflight, &id);
		status = algo >= 0 ? CONTENT_HASH_OK : CONTENT_HASH_ERROR;
	}

	e = content_reserve(CONTENT_KIND_PRE_WRITE, inode);
	if (!e)
		return 0;
	e->content.flags = file->f_flags;
	e->content.hash_status = status;
	e->content.hash_algo = algo;
	__builtin_memcpy(e->content.hash, digest, sizeof(digest));
	path_len = bpf_d_path(&file->f_path, e->content.filepath, sizeof(e->content.filepath));
	if (path_len < 1) {
		e->content.path_error = (int)path_len;
		e->content.filepath[0] = '\0';
	}
	bpf_ringbuf_submit(e, 0);
	return 0;  /* observe only, never deny */
}

SEC("lsm/file_free_security")
int BPF_PROG(content_file_free, struct file *file)
{
	struct content_inode_key key;
	struct inode *inode;
	struct event *e;

	if (!trace_content)
		return 0;
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;
	inode = BPF_CORE_READ(file, f_inode);
	if (!content_regular_file(inode))
		return 0;
	content_key(inode, &key);
	/* Only inodes the agent opened for writing (or renamed) are in
	 * content_seen, so this lookup is the scope check. A process check would
	 * be wrong here: the final fput can run after sched_process_exit, or in a
	 * kworker (delayed fput). */
	if (!bpf_map_lookup_elem(&content_seen, &key))
		return 0;

	e = content_reserve(CONTENT_KIND_WRITE_CLOSE, inode);
	if (!e)
		return 0;
	e->content.flags = BPF_CORE_READ(file, f_flags);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("lsm.s/path_rename")
int BPF_PROG(content_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct inode *moved, *victim;
	struct content_inode_key key;
	struct event *e;
	u8 track = CONTENT_SEEN_TRACK;

	if (!trace_content)
		return 0;
	moved = old_dentry->d_inode;
	if (!content_regular_file(moved) || !content_in_scope())
		return 0;
	victim = new_dentry->d_inode;

	/* Releases of the moved inode should be paired from now on. NOEXIST keeps
	 * a HASHED entry, and a TRACK entry still lets file_open measure it. */
	content_key(moved, &key);
	bpf_map_update_elem(&content_seen, &key, &track, BPF_NOEXIST);
	/* The replaced inode loses its last name: forget it so a later file that
	 * reuses its inode number is measured as new. */
	if (victim && !(flags & RENAME_EXCHANGE) && victim->i_nlink <= 1) {
		struct content_inode_key old;

		content_key(victim, &old);
		bpf_map_delete_elem(&content_seen, &old);
	}

	e = content_reserve(CONTENT_KIND_RENAME, moved);
	if (!e)
		return 0;
	e->content.flags = flags;
	if (victim)
		e->content.replaced_ino = victim->i_ino;
	content_dir_name_path(e, new_dir, new_dentry);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("lsm.s/path_unlink")
int BPF_PROG(content_path_unlink, const struct path *dir, struct dentry *dentry)
{
	struct inode *inode;
	struct event *e;
	unsigned int nlink;

	if (!trace_content)
		return 0;
	inode = dentry->d_inode;
	if (!content_regular_file(inode) || !content_in_scope())
		return 0;

	nlink = inode->i_nlink;
	if (nlink <= 1) {
		struct content_inode_key key;

		content_key(inode, &key);
		bpf_map_delete_elem(&content_seen, &key);  /* see path_rename */
	}
	e = content_reserve(CONTENT_KIND_UNLINK, inode);
	if (!e)
		return 0;
	e->content.nlink = nlink;
	content_dir_name_path(e, dir, dentry);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(content_fork, struct task_struct *parent, struct task_struct *child)
{
	u32 child_tgid;
	u8 one = 1;

	if (!trace_content)
		return 0;
	child_tgid = BPF_CORE_READ(child, tgid);
	if (child_tgid == BPF_CORE_READ(parent, tgid))
		return 0;  /* a new thread, its process is already decided */
	if (!content_in_scope())  /* current == parent here */
		return 0;
	bpf_map_update_elem(&content_scope_pids, &child_tgid, &one, BPF_ANY);
	return 0;
}

#endif /* __PROCESS_EXT_BPF_CONTENT_H */
