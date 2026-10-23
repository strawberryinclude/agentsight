# File content hashes in AgentSight: design, trade-offs, experiment

This fork extends AgentSight's observer so that, for every file an agent
touches, the trace records the SHA-256 of the content **before the agent's
first modification** and **after its last write**. Like the rest of
AgentSight, the extension observes from the kernel boundary with eBPF, keeps
overhead low, and adds nothing to the agent.

- Code: two commits on top of upstream `85bdb15` (branch `content-hash`).
- Design reference: [`docs/content-hash.md`](docs/content-hash.md).
- Experiment capture: [`experiments/`](experiments/).

```console
$ sudo agentsight record -- claude          # hashing is on by default
$ agentsight report files                   # one row per file: before / after
$ agentsight report files --all --json      # full hashes and where each was measured
```

## 1. Problem

AgentSight records that an agent opened, wrote, or executed a file, not what
the file contained. An agent reads a file, reasons over it, and writes a new
version back, so a trace cannot show what a file looked like before the agent
touched it or what the agent left behind.

Two hashes per file answer that, and they can be checked against `sha256sum`,
a backup, or a git object. The hard one is "before": it must be measured
before the agent can change the file, and the observer runs asynchronously
from the agent.

## 2. Feasibility: what the kernel can measure, and when

Linux 5.18 added `bpf_ima_file_hash()`, which lets a BPF program hash a file
with the kernel's IMA subsystem. Only the 32-byte digest leaves the kernel,
never the content. It can only be called from **sleepable** programs, and
only a few LSM hooks are sleepable. The question was whether a sleepable
`file_open` hook sees the content before the opener can change it.

A small probe (`bpf/imaprobe.*`, first commit) answered this on the target
system: Ubuntu 22.04 ARM64 with the 6.8 HWE kernel. The stock 5.15 kernel is
too old for the helper.

| # | Probe | Finding | Consequence |
|---|---|---|---|
| F1 | `tee -a` (append) and `tee` (`O_TRUNC`) | The hash at `file_open` equals `sha256sum` before the append and before the truncation | "Before" can be exact for writable opens |
| F2 | `cat` (read-only) | IMA fails with `-EOPNOTSUPP` | Read-only opens must be hashed elsewhere |
| F3 | `file_release` hook | Not in the 6.8 kernel | "After" needs another hook |
| F4 | IMA during the probe | IMA re-opens the file, which shows up as an extra open | Must be filtered from the trace |

F2 has a precise cause: the hook runs inside `do_dentry_open()` before
`FMODE_CAN_READ` is set, and IMA only works around that for files opened
without `FMODE_READ`. So `O_WRONLY` can be hashed at the hook; `O_RDONLY` and
`O_RDWR` cannot.

## 3. Design

| Kernel hook | When | What it does |
|---|---|---|
| `lsm.s/file_open` | First writable open of an inode by the agent | Hashes it with IMA before `open()` returns and before `O_TRUNC` |
| `lsm/file_free_security` | Last reference to a writable file is dropped | Reports "may have changed" (no hash) |
| `lsm.s/path_rename` | Agent renames a file | Records new path and the inode it replaced |
| `lsm.s/path_unlink` | Agent deletes a file | Records the deletion |
| `tp_btf/sched_process_fork` | An in-scope process forks | Puts the child in scope before it runs |

User space (the existing C loader) turns these into `FILE_CONTENT` events, and
the Rust side folds them into one row per file.

**Before.** For writable opens, the hash is computed in the kernel at the only
moment nothing can race with it: inside the open, before the agent has a file
descriptor. For read-only opens, the loader hashes the file in user space as
soon as it sees the open event. The read hash serves as the "before" when the
agent later replaces the file. Every user-space read checks with `fstat()`
that it opened the same (device, inode) the kernel reported. If the path now
names a different file, the result is `inode_mismatch`, never a wrong hash.

**After.** No release hook is sleepable, on 6.8 or later (checked up to 6.12),
so IMA cannot run at close. The kernel reports the last release through
`file_free_security`, which covers `close()`, process exit, `munmap` and
duplicated descriptors in one place. User space hashes 500 ms after the last
release, so a burst of writes costs one hash.

**Atomic replace.** Editors and agents often write `x.tmp` and rename it over
`x`. That involves two inodes. The rename hook links them, and the report
follows the chain: "before" comes from the original inode, "after" from the
last one.

**Scope.** "The agent" is decided in the kernel, without waiting for user
space:
- processes in the traced command's session, or
- processes in a scope map that the kernel fills at fork time.

The fork rule is needed because agents start tool commands with `setsid()`.

**Failure isolation.** Hashing is on by default, so it must never break the
tracer. The loader tries the content programs, falls back without them if
they do not load or attach, and reports why in a `CONTENT_HASH_CONFIG` event.

## 4. Trade-offs

| Decision | Alternative | Why |
|---|---|---|
| Hash inside `open()` for writable opens | Hash in user space after the open event | User space is always late: `O_TRUNC` or the first write may already have happened. The cost is that the agent's `open()` waits for the hash (about 0.13 ms per 64 KiB file, section 5). |
| "After" in user space after the last release | In the kernel at close | Impossible: no sleepable release hook exists. Cost: a non-agent writer within 500 ms of the release would be included. |
| `file_free_security` | fentry on `filp_close` or `filp_flush` | One hook for every way a file is released. `filp_flush` is small and may be inlined, and an fentry probe would then silently miss it. |
| Each inode hashed once per session, at its first writable open | Every open | Overhead stays bounded. Only the first modification matters for "before". |
| Stay on 6.8 | Require 6.9+ (`file_post_open`) | The target distribution ships 6.8. On a newer kernel, `file_post_open` would also hash read-only and `O_RDWR` opens in the kernel; the loader's per-hook feature detection is where that would plug in. |
| Unknown rather than guessed | Fall back to hashing the current path | A wrong "before" is worse than none for an audit trail. |

## 5. Experiment on a real agent

`scripts/content_hash_experiment.sh` sets up a small project and records
Claude Code 2.1.302 under `agentsight record`. The agent is asked to:
- read `notes.txt`
- fix a bug in `calc.py`
- edit `config.json`
- append to `README.md`
- delete `old.log`
- create `CHANGES.md`

The script then compares every reported hash with `sha256sum` taken outside
the trace.

The experiment was run three times. Claude chose different tools in
different runs, so between them every path of the design was exercised on a
real agent. Run 3 used the final code.

| File | What Claude did | Before from | Runs 1–3 |
|---|---|---|---|
| `README.md` | runs 1 and 3: append in place; run 2: Edit (temp + rename) | kernel IMA / read hash | match |
| `calc.py`, `config.json` | Edit (temp + rename) | read hash | match |
| `notes.txt` | `cat` in a Bash tool shell (`setsid`) | read hash | match |
| `old.log` | `cat`, then `rm` in a Bash tool shell | read hash | match, recorded as deleted |
| `CHANGES.md` | Write tool, new file | none (created) | match |

All three runs: `all hashes match sha256sum` (`experiments/claude-run-*/comparison.txt`).
The covered paths were:
- the in-kernel "before"
- the rename chain
- read hashes
- deletion
- creation

**Overhead and stress** (`scripts/content_hash_overhead.sh`). The workload
edits 200 files of 64 KiB: half in place, half with temp + rename. It times
itself, so the numbers are what the traced program sees. Median of 5 runs:

| | Workload time | Correctness |
|---|---|---|
| no tracing | 21.4 ms | |
| `record --no-content-hash` | 33.4 ms | |
| `record` (hashing) | 60.2 ms | 200/200 "after" correct; 100/100 in-place "before" exact (kernel); 100 replaced files "before" unknown; **0 wrong** |

Hashing adds about 0.13 ms per edited file (`experiments/overhead.txt`). Most of that is the in-kernel
SHA-256 inside `open()`. Real agents spend seconds per tool call, so this is
not noticeable there.

The 100 unknown "before" hashes are the limit described in section 2. This
workload replaces each file about 0.1 ms after reading it, which is faster
than user space can hash the read. All 100 were refused as `inode_mismatch`
rather than reported with the new file's hash.

## 6. Problems the experiment exposed (and fixes)

A first attempt recorded neither `notes.txt` nor the deletion of `old.log`.
Finding out why found four problems, two of them in upstream AgentSight:

1. **Agent commands leave the session.** Claude Code runs each Bash tool
   command under `setsid()`. AgentSight followed only the session, so these
   commands were missing from the whole trace, not only from hashing.
   - Fix: the kernel adds every child of an in-scope process to the scope at
     fork, before it runs.
   - Fix: the process tracker also follows the parent chain.
2. **Fixed start-up delay.** `record` released the agent 250 ms after
   starting the tracer. With the content programs, verification can take
   longer than that.
   - Fix: the tracer prints `AGENTSIGHT_PROCESS_READY` once its programs are
     attached, and `record` waits for it. This is the handshake the TLS probe
     already used.
3. **System-wide events crowd out the agent.** The resolved-open tracer sent
   every open on the machine through a 1 MiB ring buffer and filtered in user
   space. AgentSight's own `/proc` scan (~1000 opens every 2 s) overflowed it,
   and agent events in that window were lost.
   - Fix: with the kernel-side scope from fix 1, opens are filtered in the
     kernel. This also lowers overhead.
4. **Silent loss under bursts.** In the stress test, half the files were
   missing and nothing said so. The tracer counted the drops, but the analysis
   side ignored the counters.
   - Fix: with hashing on, the ring is 16 MiB.
   - Fix: lost events are stored, and `report files` warns that the list may
     be incomplete.

Two practical points also mattered:
- The collector embeds a copy of the tracer, so a plain `cargo build` ran
  stale code. The experiment script now refuses to run in that case.
- The TLS probe does not support this Claude Code build, so the experiment
  uses `record --no-ssl`. File hashing does not depend on TLS capture.

## 7. Limitations

- Read-only and `O_RDWR` opens are hashed in user space, with a small window
  (section 5). Linux 6.9+ `file_post_open` would remove it.
- "After" is the content 500 ms after the agent's last release. A
  concurrent non-agent writer in that window would be included.
- A file deleted without ever being opened has no "before": `unlink` does not
  read content, and no hook at deletion can.
- Records are fixed-size (~4.5 KiB, mostly the path buffer). Variable-size
  records would make the ring about ten times denser, but that changes
  upstream's event layout.
- On btrfs, `stat()` device numbers differ from the kernel's, so user-space
  verification reports `inode_mismatch`. ext4, xfs and tmpfs are fine.

## 8. Testing

- C unit tests (`make -C bpf unit-test`): SHA-256 known-answer vectors, the
  hashing helper's edge cases, and the event flow, using synthetic kernel
  events.
- Rust tests (`cargo test` in `ext/analysis`): per-inode lives, replace
  chains, precedence of sources, loss reporting, and a SQLite round trip.
- The scripts above for the real kernel and the real agent.
