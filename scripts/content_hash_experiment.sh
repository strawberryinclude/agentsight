#!/usr/bin/env bash
# Content-hash experiment on a real agent.
#
# Creates a small project, records the agent editing it with
# `agentsight record`, and checks AgentSight's per-file "before" and "after"
# hashes against sha256sum taken outside the trace (ground truth).
#
# Usage (as your normal user; it calls sudo for the recording):
#   scripts/content_hash_experiment.sh
# Overrides:
#   RECORD_FLAGS  extra flags for `agentsight record` (default: --no-ssl; TLS
#                 capture is not needed here and some agent builds cannot be hooked)
#   AGENT_CMD   command to trace (default: claude -p "$PROMPT" --permission-mode acceptEdits)
#   WORK        experiment directory (default: ~/agentsight-experiment)
#   AGENTSIGHT  agentsight binary (default: this repo's release build)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
AGENTSIGHT=${AGENTSIGHT:-$REPO/collector/target/release/agentsight}
WORK=${WORK:-$HOME/agentsight-experiment}
PROJECT=$WORK/project
OUT=$WORK/results
CLAUDE_BIN=${CLAUDE_BIN:-$(command -v claude || echo "$HOME/.local/bin/claude")}
PROMPT=${PROMPT:-"You are in a small project directory. Do exactly these tasks and nothing else:
1. Read notes.txt for context. Do not modify it.
2. Fix the bug in calc.py so that add(a, b) returns a + b.
3. In config.json change \"debug\": true to \"debug\": false.
4. Append the line 'Reviewed by the agent.' to README.md.
5. Delete old.log.
6. Create CHANGES.md with one bullet per change you made."}

[ -x "$AGENTSIGHT" ] || { echo "agentsight binary not found: $AGENTSIGHT (run make build)"; exit 1; }
# The collector embeds a vendored copy of bpf/process; a plain `cargo build`
# keeps the old copy. Refuse to run an experiment on a stale tracer.
if [ -f "$REPO/bpf/process" ] && ! cmp -s "$REPO/bpf/process" "$REPO/agentsight-capture/vendor/bpf/process"; then
	echo "bpf/process differs from the copy embedded in agentsight; rebuild with:"
	echo "  make -C bpf process && (cd collector && AGENTSIGHT_SYNC_VENDOR=1 cargo build --release)"
	exit 1
fi

rm -rf "$WORK"
mkdir -p "$PROJECT" "$OUT"
cd "$PROJECT"

cat > notes.txt <<'EOF'
Project notes: calc.py is a tiny calculator module. Keep changes minimal.
EOF
cat > calc.py <<'EOF'
def add(a, b):
    return a - b  # BUG: should add


def mul(a, b):
    return a * b
EOF
cat > config.json <<'EOF'
{
  "name": "demo",
  "debug": true
}
EOF
cat > README.md <<'EOF'
# Demo project

A tiny project used to observe how an agent edits files.
EOF
printf 'old log line %s\n' 1 2 3 > old.log

# Ground truth before the run.
sha256sum -- * | sort -k2 > "$OUT/before.sha256"

if [ -n "${AGENT_CMD:-}" ]; then
	read -r -a AGENT <<< "$AGENT_CMD"
else
	AGENT=("$CLAUDE_BIN" -p "$PROMPT" --permission-mode acceptEdits)
fi

echo "== Recording: ${AGENT[*]}"
# HOME is preserved so the agent (dropped back to your uid) finds its login.
read -r -a RFLAGS <<< "${RECORD_FLAGS---no-ssl}"
sudo --preserve-env=HOME "$AGENTSIGHT" record --db "$OUT/session.db" --no-server "${RFLAGS[@]}" -- "${AGENT[@]}" \
	| tee "$OUT/record.log"

# Ground truth after the run.
sha256sum -- * | sort -k2 > "$OUT/after.sha256"

"$AGENTSIGHT" report files --db "$OUT/session.db" --all | tee "$OUT/report_files.txt"
"$AGENTSIGHT" report files --db "$OUT/session.db" --all --json > "$OUT/report_files.json"
"$AGENTSIGHT" report audit --db "$OUT/session.db" --audit-type file_content --limit 10000 --json \
	> "$OUT/audit_file_content.json"

echo
echo "== Comparing AgentSight hashes with sha256sum ground truth"
python3 - "$PROJECT" "$OUT" <<'PY'
import json, os, sys
project, out = sys.argv[1], sys.argv[2]

def load(name):
    hashes = {}
    with open(os.path.join(out, name)) as f:
        for line in f:
            digest, path = line.split(maxsplit=1)
            hashes[path.strip()] = digest
    return hashes

before, after = load("before.sha256"), load("after.sha256")
rows = {os.path.realpath(r["path"]): r for r in json.load(open(os.path.join(out, "report_files.json")))}
names = sorted(set(before) | set(after))
ok = True
lines = []
for name in names:
    row = rows.get(os.path.realpath(os.path.join(project, name)))
    exp_before, exp_after = before.get(name), after.get(name)
    if row is None:
        verdict = "NOT OBSERVED"
        ok = False if exp_before != exp_after else ok
        lines.append(f"{name:<12} {verdict}")
        continue
    got_before, got_after = row.get("before_sha256"), row.get("after_sha256")
    b_ok = got_before == exp_before
    a_ok = got_after == exp_after
    b_txt = "OK " if b_ok else "BAD"
    # A file deleted without ever being opened has no measurable "before":
    # unlink does not read content and the kernel cannot read it at that hook.
    if not b_ok and got_before is None and row["outcome"] == "deleted":
        b_ok, b_txt = True, "n/a (deleted unread)"
    ok &= b_ok and a_ok
    lines.append(f"{name:<12} {row['outcome']:<9} {row['method']:<14} "
                 f"before {b_txt} ({row.get('before_source') or '-'})  "
                 f"after {'OK ' if a_ok else 'BAD'} ({row.get('after_source') or '-'})")
print("\n".join(lines))
print("\nRESULT:", "all hashes match sha256sum" if ok else "MISMATCHES, see above")
with open(os.path.join(out, "comparison.txt"), "w") as f:
    f.write("\n".join(lines) + "\nRESULT: " + ("PASS" if ok else "FAIL") + "\n")
PY
echo
echo "Artifacts in $OUT: session.db, record.log, before/after.sha256, report_files.{txt,json},"
echo "audit_file_content.json, comparison.txt"
