#!/usr/bin/env bash
# Overhead and correctness of content hashing on a deterministic file-editing
# workload.
#
# The workload edits N files of SIZE_KB each: half in place, half by writing a
# temp file and renaming it over the target (like many editors and agents). It
# times itself, so the numbers are what the traced program experiences, not
# AgentSight's start-up and shutdown. Three arms, RUNS runs each:
#   baseline        no tracing
#   record          agentsight record --no-content-hash
#   record+hash     agentsight record (content hashing on)
# Both record arms use --no-ssl so the comparison isolates the process tracer.
# Afterwards, the last record+hash run is checked file by file against
# sha256sum: every file must have the right "before" and "after" hash.
#
# Usage: scripts/content_hash_overhead.sh   (env: N=200 SIZE_KB=64 RUNS=5)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
AGENTSIGHT=${AGENTSIGHT:-$REPO/collector/target/release/agentsight}
N=${N:-200}
SIZE_KB=${SIZE_KB:-64}
RUNS=${RUNS:-5}
WORK=${WORK:-$HOME/agentsight-overhead}
sudo rm -rf "$WORK"
mkdir -p "$WORK"

WORKLOAD="$WORK/workload.py"
cat > "$WORKLOAD" <<'PY'
import os, sys, time
root, n, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
start = time.perf_counter()
for i in range(n):
    path = os.path.join(root, f"f{i:04d}.txt")
    with open(path) as f:
        data = f.read()
    data = data.replace("x", "y", 1) + f"edit {i}\n"
    if i % 2:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(data)
        os.replace(tmp, path)
    else:
        with open(path, "w") as f:
            f.write(data)
with open(out, "w") as f:
    f.write(f"{(time.perf_counter() - start) * 1000:.1f}\n")
PY

prepare() {
	rm -rf "$WORK/files"
	mkdir -p "$WORK/files"
	python3 - "$WORK/files" "$N" "$SIZE_KB" <<'PY'
import os, sys
root, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]) * 1024
for i in range(n):
    with open(os.path.join(root, f"f{i:04d}.txt"), "w") as f:
        f.write(("x" * 63 + "\n") * (size // 64))
PY
}

# measure LABEL CMD...: RUNS runs; the time comes from inside the workload.
measure() {
	local label=$1; shift
	local times=()
	for run in $(seq "$RUNS"); do
		prepare
		sha256sum "$WORK"/files/* | sort -k2 > "$WORK/before.sha256"
		sudo rm -f "$WORK/$label.db"
		"$@" python3 "$WORKLOAD" "$WORK/files" "$N" "$WORK/t.txt" > "$WORK/$label.log" 2>&1
		times+=("$(cat "$WORK/t.txt")")
	done
	printf '%s\n' "${times[@]}" | python3 -c '
import statistics, sys
t = sorted(float(x) for x in sys.stdin)
print(f"{sys.argv[1]:<12} median {statistics.median(t):7.1f} ms   min {t[0]:7.1f}   max {t[-1]:7.1f}   (n={len(t)})")
' "$label"
}

sudo -v
echo "Workload: $N files x ${SIZE_KB} KiB, half in place, half temp+rename; time measured inside the workload"
measure baseline env
measure record sudo "$AGENTSIGHT" record --db "$WORK/record.db" --no-server --no-ssl --no-content-hash --
measure record+hash sudo "$AGENTSIGHT" record --db "$WORK/record+hash.db" --no-server --no-ssl --
sha256sum "$WORK"/files/* | sort -k2 > "$WORK/after.sha256"

echo
echo "== Correctness of the last record+hash run (every file vs sha256sum)"
"$AGENTSIGHT" report files --db "$WORK/record+hash.db" --json > "$WORK/report.json"
python3 - "$WORK" <<'PY'
import collections, json, os, sys
work = sys.argv[1]
def load(name):
    out = {}
    for line in open(os.path.join(work, name)):
        digest, path = line.split(maxsplit=1)
        out[os.path.realpath(path.strip())] = digest
    return out
before, after = load("before.sha256"), load("after.sha256")
rows = {os.path.realpath(r["path"]): r for r in json.load(open(os.path.join(work, "report.json")))}
stats = collections.Counter()
for path in sorted(after):
    r = rows.get(path)
    if r is None:
        stats["missing"] += 1
        continue
    stats[f"{r['outcome']}/{r['method']}"] += 1
    stats[f"before from {r.get('before_source')}"] += 1
    for side, truth in (("before", before[path]), ("after", after[path])):
        got = r.get(f"{side}_sha256")
        stats[f"{side} " + ("ok" if got == truth else "unknown" if got is None else "WRONG")] += 1
n = len(after)
for key in sorted(stats):
    print(f"  {key:<28} {stats[key]:4d} / {n}")
# A wrong hash is a bug. An unknown "before" is the documented limit of
# read-only opens on this kernel: the agent replaced the file before user
# space hashed what it had read, and the inode check refused to guess.
wrong = stats["before WRONG"] + stats["after WRONG"] + stats["missing"]
if wrong:
    print("RESULT: MISMATCHES")
elif stats["before unknown"] or stats["after unknown"]:
    print(f"RESULT: no wrong hashes; {stats['before unknown']} 'before' and "
          f"{stats['after unknown']} 'after' unknown")
else:
    print("RESULT: all files correct")
PY
