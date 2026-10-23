# File content hashes

AgentSight records which files an agent opens. With content hashing it also
records, for every regular file the agent touches:

- the SHA-256 of the content **before the agent's first modification**, and
- the SHA-256 of the content **after the agent's last write**.

A trace can then show what a file looked like before the agent touched it and
what the agent left behind, and the hashes can be checked against backups,
git objects, or `sha256sum`.

`agentsight record` enables it by default (`--no-content-hash` turns it off).
The process tracer flag is `--content-hash` (size limit:
`--content-hash-max-mb`, default 16).

```console
$ sudo agentsight record -- claude
$ agentsight report files            # files the agent wrote, created, deleted
$ agentsight report files --all      # also files it only read
$ agentsight report files --json     # full hashes and where each was measured
```

## Requirements

- Linux with BPF LSM active: `cat /sys/kernel/security/lsm` must list `bpf`
  (add it to the `lsm=` boot parameter otherwise).
- IMA compiled in (`CONFIG_IMA=y`, the default on Ubuntu, Fedora, Debian).
  `bpf_ima_file_hash()` needs Linux 5.18 or later.
- `CONFIG_SECURITY_PATH=y` for rename and unlink tracking (default on distros
  that ship AppArmor or TOMOYO).

When a requirement is missing the tracer prints a `CONTENT_HASH_CONFIG` event
with the reason and keeps tracing everything else. Content hashing never takes
down the rest of AgentSight.

## Design

### Principle: measure at the kernel boundary, at the one moment that cannot race

The hard part is "before any modification". If the observer learns about an
open and reads the file afterwards, the agent may already have written it, or
truncated it with `O_TRUNC`. So the measurement has to happen inside the open,
before the agent receives the file descriptor.

The BPF LSM hook `file_open` runs exactly there: after path resolution, before
`open(2)` returns, and before `O_TRUNC` truncates the file. A sleepable BPF LSM
program (`lsm.s/file_open`) can call `bpf_ima_file_hash()`, which uses the
kernel's IMA subsystem to hash the file content in the kernel. No content
crosses the kernel boundary, only 32 bytes of digest.

A feasibility probe (`bpf/imaprobe.bpf.c`) checked this on Ubuntu 22.04 with
the 6.8 HWE kernel, comparing against `sha256sum`:

| open                  | in-kernel hash at `file_open`               |
|-----------------------|---------------------------------------------|
| `tee -a` (append)     | equals `sha256sum` before the append        |
| `tee` (`O_TRUNC`)     | equals `sha256sum` before the truncation    |
| `cat` (read-only)     | fails with `-EOPNOTSUPP`                    |
| `file_release` hook   | does not exist on 6.8                       |

These four results shape the design, together with one consequence found in
review: an `O_RDWR` open cannot be hashed at this hook either (below).

### Hooks (`bpf/process_ext/bpf_content.h`)

| hook | when | what the kernel does |
|---|---|---|
| `lsm.s/file_open` | first **writable** open of an inode by the agent in this session | hash with IMA, emit `PRE_WRITE` with the digest |
| `lsm/file_free_security` | last reference to a writable open file of a measured inode is released | emit `WRITE_CLOSE` (no hash) |
| `lsm.s/path_rename` | the agent renames a regular file | emit `RENAME`: inode, new path, inode it replaced |
| `lsm.s/path_unlink` | the agent deletes a regular file | emit `UNLINK` |
| `tp_btf/sched_process_fork` | an in-scope process forks | add the child to the scope, before it runs |

**Which opens the kernel can hash.** In `do_dentry_open()` the LSM hook runs
before the file is fully open: `FMODE_CAN_READ` is set only after the
filesystem's `->open()`, and IMA's read path (`__kernel_read`) requires it.
IMA works around this only for files without `FMODE_READ`: it then opens a
private, fully opened read-only instance (`ima_calc_file_hash()`). Hence:

| open mode | kernel hash at `file_open` | fallback |
|---|---|---|
| `O_WRONLY` (`"w"`, `"a"`: editors, agents, shells) | exact | - |
| `O_RDWR` without `O_TRUNC` | not possible (`rdwr`) | user-space hash right after, `userspace_late` |
| `O_RDWR \| O_TRUNC` (`"w+"`) | not possible | none: the content is gone when user space looks; a prior read hash is used if there is one |
| `O_RDONLY` | not possible | user-space hash after the `FILE_OPEN` event (`read`) |

IMA's private open re-enters `security_file_open()`. BPF LSM programs have no
recursion protection, and the existing `fexit/security_file_open` tracer would
report it as an agent read; a per-thread in-flight map makes both skip it.

**Why the "after" hash is not computed in the kernel.** No sleepable LSM hook
runs when a file is released, so no release hook can call IMA. This is not a
6.8 limitation: `file_release` was added in 6.9 (the probe confirmed it is
absent on 6.8), but it is not in the sleepable hook set either (checked in the
6.12 source), and neither is `file_free_security`. The kernel
reports the release and user space hashes. `file_free_security` runs in
`__fput()` when the **last** reference goes away, so close(2), process exit,
`munmap` of a shared mapping and duplicated descriptors are all covered, and no
write through that file can follow. Hooking `filp_flush()`/`filp_close()` was
rejected: `filp_flush()` is small and may be inlined into close(2), where an
fentry probe would silently miss it.

**Inode reuse.** ext4 gives a freed inode number to the next new file almost
immediately, which repeated atomic saves trigger constantly. The kernel drops
an inode from `content_seen` when its last link goes away (unlink, or replaced
by a rename), so the next file with that number is measured as new; user space
and the Rust view start a new "life" for the number, with its own row.

**Scope.** "The agent" is decided in the kernel, without waiting for user
space: the process's session id equals the traced command's session (all
descendants inherit it), or the pid is in `content_scope_pids`. The kernel adds
every child of an in-scope process to that map at fork, before the child runs;
user space adds seeds and `-p`/`-c` matches and removes pids on exit. The fork
rule matters for real agents: Claude Code runs each Bash tool command in a new
session (`setsid()`), so the session check alone misses them, and adding the
pid from user space after the exec event loses the race against a short
command: in the first experiment run, `rm old.log` finished before user space
had seen its exec. The same run showed that AgentSight's process tracker itself
followed only the session, so those commands were missing from the whole
trace; it now also follows the parent chain and the kernel scope map.
The release hook uses a different scope check, membership of the inode in
`content_seen`, because the final release can run after the process's exit
event or in a kworker (delayed fput).

### User space (`bpf/process_ext/content.h`, in the C loader)

The loader turns kernel events into `FILE_CONTENT` JSON events, one per phase:

| phase | source | meaning |
|---|---|---|
| `before_write` | `kernel_ima` | content right before the first write (exact) |
| `read` | `userspace` | content when the agent first opened the file read-only |
| `after_write` | `userspace` | content after the last write (debounced) |
| `renamed` | kernel | inode moved to a path, maybe replacing another inode |
| `deleted` | kernel | inode unlinked |

- **Read-only files** are hashed right after their `FILE_OPEN` event, once per
  inode, up to 4 MiB (this runs inside the ring buffer callback, so it must
  stay short). Content cannot change through a read-only descriptor; it is only wrong
  if another process writes the file in the few milliseconds between the open
  and the hash. If the agent later writes the file, the exact kernel
  `before_write` hash takes precedence.
- **After-write** waits 500 ms without further releases of the inode, then
  hashes once. A burst of writes costs one hash, and the value is the content
  after the last write. If size and mtime/ctime are unchanged since the last
  after-write hash, it is not re-read.
- **Verified reads.** Every user-space read opens the path (through
  `/proc/<pid>/root` first, so container paths resolve in the agent's mount
  namespace), then checks with `fstat()` that it got the same (dev, inode) the
  kernel reported. A path that now names another file is reported as
  `inode_mismatch`, never as a wrong hash. Files are opened with `O_NOATIME`, so
  observing does not change them.
- SHA-256 in user space is a small FIPS 180-4 implementation, so the loader's
  dependencies are unchanged; it matches the kernel's SHA-256 (the IMA default
  on Ubuntu; other IMA algorithms are reported but not labelled sha256).

### Rust (`ext/analysis/src/view/file_content.rs`)

`FILE_CONTENT` events are folded into one audit row per inode life
(`audit_type = "file_content"`, upserted as phases arrive), stored in the
session SQLite database with the other audit events. "Before" uses the best
available measurement: the exact kernel hash, else the first read-only hash
(it precedes the write), else the `userspace_late` fallback.

`agentsight report files` turns the rows into one row per path. An atomic
replace (write `x.tmp`, rename over `x`) involves two inodes, and repeated saves
form a chain; the report follows the chain: "before" from the original inode,
"after" from the last one.

## Failure isolation

Content hashing is on by default in `record`, so it must never break the rest
of the tracer. The loader tries (content, resolved opens), (content, syscall
opens), (resolved), (syscall) until one loads, and attaches the content hooks
separately from the skeleton: if `file_open` or `file_free_security` cannot
attach, hashing is disabled and everything else keeps running; rename/unlink
are optional. The outcome is reported in a `CONTENT_HASH_CONFIG` event.

`record` releases the launched agent only after the process tracer prints
`AGENTSIGHT_PROCESS_READY` on stderr (programs attached, ring buffer open).
Before, only the TLS probe had a readiness handshake and the process tracer
got a fixed 250 ms; with `--no-ssl`, a command that ran during program
verification (several hundred ms with the content hooks) was not traced.

## Overhead

- Every hook exits after a few field loads unless the file is a regular file
  on a real filesystem, opened for writing (or renamed, unlinked) by an
  in-scope process. Pseudo filesystems (`/proc`, `/sys`, cgroupfs, ...) are
  skipped in the kernel.
- The kernel hashes each inode at most once per session (`content_seen` LRU
  map), and only on its first writable open. That hash runs synchronously in
  the agent's `open()`: this is the price of a race-free "before". Files above
  the size limit are skipped (`too_large`).
- The release hook is a map lookup for writable files; user-space work is
  debounced.
- In `record` (session mode) the kernel knows the whole agent tree once the
  fork hook is attached, so the existing resolved file-open tracer drops opens
  of other processes in the kernel. Before, it sent every open on the machine
  through the ring buffer and filtered in user space; AgentSight's own `/proc`
  scan (about 1000 opens every 2 s) then overflowed the 1 MiB ring, and agent
  events that happened during the burst were lost. A command that ran at
  startup, during the first scan, was missing from the trace.
- `scripts/content_hash_overhead.sh` measures a deterministic workload with and
  without hashing.

## Newer kernels

Upgrading past 6.8 does not move the "after" hash into the kernel (see above),
but it would improve "before". Linux 6.9 added the `file_post_open` LSM hook,
and as of 6.12 it is sleepable. In `do_open()` it runs after `vfs_open()`
(the file is fully open, `FMODE_CAN_READ` is set) and before
`handle_truncate()`:

```c
error = vfs_open(&nd->path, file);
if (!error)
        error = security_file_post_open(file, op->acc_mode);
if (!error && do_truncate)
        error = handle_truncate(idmap, file);
```

A `lsm.s/file_post_open` program could therefore hash read-only and `O_RDWR`
opens in the kernel too, still before `O_TRUNC` and before the opener gets the
fd, removing the `read` and `userspace_late` user-space fallbacks. It was not
implemented because the target system (Ubuntu 22.04, newest supported kernel
6.8) cannot run it; the loader's per-hook feature detection is where it would
plug in.

## Limitations

- **Read-then-replace bursts.** An atomic replace never opens the original
  file for writing, so its "before" is the user-space hash of the agent's
  read-only open. That hash happens when user space processes the open event;
  if the agent has already renamed a new file over the path, the inode check
  fails and "before" stays unknown (it is never taken from the wrong file).
  Real agents read, think for seconds, then write, and the experiments always
  had the read hash. The overhead benchmark edits 200 files in about 20 ms:
  all 100 in-place files had the exact kernel "before", all 200 "after" hashes
  were right, and the 100 atomically replaced files had no "before" because
  user space was always behind the workload. Linux 6.9+ `file_post_open`
  (see above) would hash read-only opens in the kernel and remove this window.
- **`O_RDWR` opens** are not measured in the kernel (see the table above). The
  `userspace_late` fallback is right unless the agent writes within a few
  milliseconds of opening; with `O_TRUNC` there is no fallback.
- **Content changed by others.** "After" is the content when the agent's last
  writable file reference was released (+500 ms). A non-agent writer in that
  window would be included. Read-only hashes have the same small window.
- **Deleted without being read**: `unlink` never reads content, and no hook
  at deletion can read it (`path_unlink` gets a dentry, not an open file, and
  IMA only hashes open files), so such a file has a `deleted` row without a
  "before" hash. If the agent read or wrote it earlier, that hash is kept.
- **Files opened before tracing started** (inherited descriptors) have no
  `before_write`; their releases are not paired.
- **Memory-mapped writes** are covered when the mapping is the last reference
  (munmap releases the file); `msync` without unmap is not an event.
- **Hard links**: a file is an inode; a second name is reported under the
  last path seen.
- **`RENAME_EXCHANGE`** swaps two files; only the moved inode's new path is
  recorded.
- **btrfs** reports per-subvolume device numbers in `stat()` that differ from
  the kernel's `s_dev`, so user-space verification reports `inode_mismatch`.
  ext4, xfs and tmpfs are fine.
- **Overlay/container layers**: the kernel may see both the overlay and the
  backing inode; both are measured.
- **Bursts.** Each tracer record is a full `struct event` (about 4.5 KiB, most
  of it the path buffer), and hashing adds 2-4 records per edited file. With
  hashing on, the ring buffer is 16 MiB instead of 1 MiB (about 3600 records);
  with 1 MiB the overhead benchmark (200 files edited in ~30 ms) missed half
  of the files.
  Anything dropped is still counted (`CONTENT_HASH_LOST`, `FILE_OPEN_LOST`),
  stored as a `file_content_lost` row, and `report files` prints a warning that
  the list may be incomplete. Variable-size records (path length only) would
  shrink records about tenfold; that changes the tracer's event layout and was
  left out.

## Verifying a run

`scripts/content_hash_experiment.sh` builds a small project, records Claude
Code editing it (modify, append, create, delete, read-only), and compares every
reported hash with `sha256sum` taken outside the trace.
