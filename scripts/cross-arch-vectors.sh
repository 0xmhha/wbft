#!/usr/bin/env bash
# Runs the conformance vectors whose results depend on binary64 arithmetic
# (validators/quorum and timers/round_timeout) through the vector adapter with
# the reference runner of wbft-spec, and writes the per-case results so that
# the runs of two architectures can be compared line by line.
#
# Usage: scripts/cross-arch-vectors.sh SPEC_DIR ADAPTER OUT
#   SPEC_DIR  the spec directory of a wbft-spec checkout (with vectors/ and
#             tools/vectorgen/check_adapter.py)
#   ADAPTER   the wbft-vector-adapter binary
#   OUT       output file: one line per case, "<runner>/<handler>/<case> <result>"
#             where <result> is the adapter's result object without its id
#
# Exits 1 when a case fails or is unsupported (check_adapter.py) or when no
# case ran. Requires python3 with pyyaml.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  sed -n '2,15p' "$0" >&2
  exit 2
fi
spec=$1 adapter=$2 out=$3
handlers=(validators/quorum timers/round_timeout)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for h in "${handlers[@]}"; do
  mkdir -p "$work/vectors/$(dirname "$h")"
  cp -R "$spec/vectors/$h" "$work/vectors/$h"
done

# The adapter's stdout is copied to a file on its way to the runner.
python3 "$spec/tools/vectorgen/check_adapter.py" "$work/vectors" -- \
  sh -c '"$0" | tee "$1"' "$adapter" "$work/raw.jsonl" | tee "$work/summary.txt"

# Join the results (sent in the runner's case order, after the hello line)
# with the case paths in the same order.
python3 - "$work/vectors" "$work/raw.jsonl" "$out" <<'EOF'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
cases = [str(m.parent.relative_to(root)) for m in sorted(root.glob("*/*/*/meta.yaml"))]
lines = pathlib.Path(sys.argv[2]).read_text().splitlines()[1:]
results = [json.loads(l) for l in lines]
if len(results) != len(cases):
    sys.exit(f"cross-arch-vectors: {len(cases)} cases but {len(results)} results")
with open(sys.argv[3], "w") as f:
    for c, r in zip(cases, results):
        r.pop("id", None)
        f.write(c + " " + json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
if not cases:
    sys.exit("cross-arch-vectors: no case ran")
print(f"cross-arch-vectors: {len(cases)} cases written to {sys.argv[3]}")
EOF
