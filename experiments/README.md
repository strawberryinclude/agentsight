# Experiment captures

Ubuntu 22.04 ARM64 (Parallels VM), Linux 6.8.0-138 (HWE), Claude Code 2.1.302.

| Directory | What | Code |
|---|---|---|
| `claude-run-1/` | `scripts/content_hash_experiment.sh`, 2026-10-17 18:23 | before the ring-buffer and kernel open-filter fixes |
| `claude-run-2/` | same, 2026-10-17 18:47 | before the ring-buffer fix |
| `claude-run-3-final/` | same, 2026-10-23 | final code (`run-3-commit.txt`) |
| `overhead.txt` | `scripts/content_hash_overhead.sh` | final code |

The fixes between runs 1–2 and run 3 change event delivery under load, not
hashing, and all three runs give the same result.

Files in each run directory:

- `comparison.txt`: each project file, AgentSight's "before"/"after" vs `sha256sum`
- `before.sha256`, `after.sha256`: ground truth taken outside the trace
- `report_files.txt`, `report_files.json`: `agentsight report files --all`
- `audit_file_content.json`: the per-inode rows behind the report (temp files of
  atomic replaces included)
- `record.log`: console output of `agentsight record`, including the agent's answer
- `FILTERED.txt`: what was removed

**Filtered for publication.** AgentSight records every file the agent's
process tree touches, which includes Claude Code's own files in the home
directory (configuration, the credentials file, caches). Only rows for the
experiment project are kept, and the full session databases (`session.db`)
are not published. `scripts/content_hash_experiment.sh` reproduces the
complete capture.
