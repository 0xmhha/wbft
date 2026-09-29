#!/usr/bin/env bash
# kvstore-devnet.sh: run the kvstore example as a local network of
# separate processes and check it end to end.
#
# It builds bin/wbft-kvstore, writes a network of N validators (default 4)
# into a temporary directory, starts one process per node, submits
# transactions to node 0, requires every node to reach the same state,
# stops the last node, lets the others continue, restarts it and requires
# it to catch up. All processes are stopped at exit.
#
# Usage: scripts/kvstore-devnet.sh [N]    (from the module root)
# Needs: curl.
set -euo pipefail

n=${1:-4}
root=$(pwd)
work=$(mktemp -d)
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$root/bin/wbft-kvstore" ./examples/kvstore/cmd/wbft-kvstore
bin="$root/bin/wbft-kvstore"
p2p=$((20000 + RANDOM % 20000))
http=$((p2p + 100))
"$bin" init -dir "$work" -nodes "$n" -p2p-port "$p2p" -http-port "$http" -epoch-length 10 >/dev/null

start() {
  "$bin" start -home "$work/node$1" 2>>"$work/node$1.log" &
  pids[$1]=$!
}
url() { echo "http://127.0.0.1:$((http + $1))"; }
height() { curl -sf "$(url "$1")/status" | sed -n 's/.*"height":"\([0-9]*\)".*/\1/p'; }
value() { curl -sf "$(url "$1")/kv/$2" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p'; }
wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS > deadline)); then
      echo "FAIL: $what"
      tail -n 20 "$work"/node*.log
      exit 1
    fi
    sleep 0.5
  done
  echo "ok   $what"
}
at_least() { local h; h=$(height "$1") && [[ -n $h && $h -ge $2 ]]; }
has_value() { [[ $(value "$1" "$2") == "$3" ]]; }

for ((i = 0; i < n; i++)); do start "$i"; done
for ((i = 0; i < n; i++)); do wait_for 60 "node $i reaches height 3" at_least "$i" 3; done

from=0x00000000000000000000000000000000000000a1
for nonce in 0 1 2; do
  curl -sf -X POST "$(url 0)/tx" -d "{\"from\":\"$from\",\"nonce\":$nonce,\"key\":\"greeting\",\"value\":\"hello-$nonce\"}" >/dev/null
done
for ((i = 0; i < n; i++)); do wait_for 60 "node $i has the value" has_value "$i" greeting hello-2; done

last=$((n - 1))
kill "${pids[$last]}"
wait "${pids[$last]}" 2>/dev/null || true
target=$(($(height 0) + 12))
wait_for 90 "the others pass height $target (an epoch block) without node $last" at_least 0 "$target"
curl -sf -X POST "$(url 1)/tx" -d "{\"from\":\"$from\",\"nonce\":3,\"key\":\"greeting\",\"value\":\"again\"}" >/dev/null
start "$last"
wait_for 90 "node $last catches up" at_least "$last" "$target"
wait_for 60 "node $last has the new value" has_value "$last" greeting again

h=$(height "$last")
info=$(curl -sf -X POST "$(url 0)/rpc" -d '{"jsonrpc":"2.0","id":1,"method":"wbft_nodeInfo"}' | grep -o '"impl":"wbft"' || true)
[[ -n $info ]] || { echo "FAIL: wbft_nodeInfo"; exit 1; }
echo "ok   wbft_nodeInfo answers"
echo "kvstore-devnet: $n nodes, node $last at height $h"
