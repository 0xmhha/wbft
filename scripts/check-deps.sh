#!/usr/bin/env bash
# check-deps.sh: fail when the build graph of the wbft module contains a
# module outside the allow-list, a go-ethereum older than v1.17.0 or not in
# the v1.17 line, or the execution-layer SDK.
#
# Usage: scripts/check-deps.sh            (from the module root)
# The list must match the "modules" rule of .golangci.yml.
set -euo pipefail

allowed=(
  github.com/0xmhha/wbft
  github.com/ethereum/go-ethereum
  github.com/supranational/blst
  github.com/prometheus/client_golang
  github.com/BurntSushi/toml
  github.com/holiman/uint256
  github.com/cockroachdb/pebble
)

# Modules that provide packages linked into wbft (test dependencies included).
mods=$(go list -deps -test -f '{{with .Module}}{{.Path}}{{end}}' ./... | sort -u)

status=0
for m in $mods; do
  ok=0
  for a in "${allowed[@]}"; do
    [[ "$m" == "$a" ]] && ok=1 && break
  done
  if [[ $ok -eq 0 ]]; then
    echo "check-deps: module $m is not in the allow-list" >&2
    status=1
  fi
done

# The embedded build resolves go-ethereum to the go-stablenet fork, which
# carries upstream v1.17 changes; older or newer lines break that build.
if grep -q 'github.com/ethereum/go-ethereum ' go.mod; then
  v=$(go list -m -f '{{.Version}}' github.com/ethereum/go-ethereum)
  if [[ ! "$v" =~ ^v1\.17\.[0-9]+ ]]; then
    echo "check-deps: go-ethereum $v is not in the v1.17.x line" >&2
    status=1
  fi
fi

if [[ $status -eq 0 ]]; then
  echo "check-deps: $(echo "$mods" | grep -c .) module(s), all allowed"
fi
exit $status
