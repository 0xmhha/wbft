#!/usr/bin/env bash
# lint-negative.sh: prove that the boundary and determinism checks fail on
# code that breaks them.
#
# The script copies the module to a temporary directory, adds one violating
# file at a time, runs the check that must catch it, and expects a failure
# whose output names the rule. It never modifies the working tree. Each case
# plays the role of a branch that CI must reject.
#
# Usage: scripts/lint-negative.sh          (from the module root)
# Needs: golangci-lint v2, network or module cache for go-ethereum v1.17.x.
set -euo pipefail

root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/wbft"
tar -C "$root" --exclude ./.git --exclude ./bin -cf - . | tar -C "$work/wbft" -xf -
cd "$work/wbft"

# The go-ethereum and extra-module cases need the modules in the graph.
GOFLAGS=-mod=mod go get github.com/ethereum/go-ethereum@v1.17.4 golang.org/x/sync@v0.22.0 >/dev/null 2>&1

(cd tools && go build -o "$work/coredet" ./lint/coredet/cmd/coredet)

fails=0
pass=0

# CHECK is lint, lint-tidy, coredet or deps.
# expect NAME CHECK FILE PATTERN: write stdin to FILE, run CHECK, and require
# a non-zero exit whose output matches PATTERN.
expect() {
  local name=$1 check=$2 file=$3 pattern=$4 out rc
  cat >"$file"
  set +e
  case $check in
    lint)
      out=$(golangci-lint run ./... 2>&1); rc=$? ;;
    lint-tidy)
      # Heavy go-ethereum packages need their whole module graph in go.sum
      # to type-check; add it for this case only.
      cp go.mod go.sum "$work/"
      GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1
      out=$(golangci-lint run ./... 2>&1); rc=$?
      cp "$work/go.mod" "$work/go.sum" . ;;
    coredet)
      out=$("$work/coredet" ./... 2>&1); rc=$? ;;
    deps)
      out=$("$root/scripts/check-deps.sh" 2>&1); rc=$? ;;
  esac
  set -e
  rm -f "$file"
  if [[ $rc -ne 0 ]] && grep -qE "$pattern" <<<"$out"; then
    echo "ok   $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name (exit $rc, want a failure matching: $pattern)"
    echo "$out" | sed 's/^/     /'
    fails=$((fails + 1))
  fi
}

# consensus imports header, so this import is also a cycle; either failure
# rejects the branch.
expect "header imports consensus" lint chain/header/zz_neg.go "header-light-verifier|import cycle not allowed" <<'EOF'
package header

import _ "github.com/0xmhha/wbft/consensus"
EOF

# An external test package has no cycle and shows the boundary rule itself.
expect "header test imports consensus" lint chain/header/zz_neg_test.go "header-light-verifier" <<'EOF'
package header_test

import _ "github.com/0xmhha/wbft/consensus"
EOF

expect "pure module imports observe" lint chain/validator/zz_neg.go "pure-layer" <<'EOF'
package validator

import _ "github.com/0xmhha/wbft/observe"
EOF

expect "chain rules import the network layer" lint chain/epoch/zz_neg.go "pure-layer" <<'EOF'
package epoch

import _ "github.com/0xmhha/wbft/p2p/transport"
EOF

expect "core imports transport" lint consensus/zz_neg.go "core-boundary" <<'EOF'
package consensus

import _ "github.com/0xmhha/wbft/p2p/transport"
EOF

expect "go-ethereum core/types" lint codec/zz_neg.go "list 'modules'.*core" <<'EOF'
package codec

import _ "github.com/ethereum/go-ethereum/core/types"
EOF

expect "go-ethereum consensus" lint-tidy codec/zz_neg.go "list 'modules'.*consensus" <<'EOF'
package codec

import _ "github.com/ethereum/go-ethereum/consensus"
EOF

expect "go-ethereum eth" lint-tidy codec/zz_neg.go "list 'modules'.*eth" <<'EOF'
package codec

import _ "github.com/ethereum/go-ethereum/eth"
EOF

expect "go-ethereum p2p" lint-tidy codec/zz_neg.go "list 'modules'.*p2p" <<'EOF'
package codec

import _ "github.com/ethereum/go-ethereum/p2p"
EOF

expect "go-ethereum outside its packages" lint chain/validator/zz_neg.go "go-ethereum-placement" <<'EOF'
package validator

import _ "github.com/ethereum/go-ethereum/common"
EOF

expect "module outside the allow-list (lint)" lint node/zz_neg.go "list 'modules'" <<'EOF'
package node

import _ "golang.org/x/sync/errgroup"
EOF

expect "module outside the allow-list (build graph)" deps node/zz_neg.go "not in the allow-list" <<'EOF'
package node

import _ "golang.org/x/sync/errgroup"
EOF

expect "randomness in a pure module" lint chain/epoch/zz_neg.go "deterministic-imports" <<'EOF'
package epoch

import _ "math/rand/v2"
EOF

expect "sync in the core" lint consensus/zz_neg.go "core-no-sync" <<'EOF'
package consensus

import _ "sync"
EOF

expect "refsort outside types and epoch" lint chain/validator/zz_neg.go "refsort-users" <<'EOF'
package validator

import _ "github.com/0xmhha/wbft/internal/refsort"
EOF

expect "clock in the core" lint consensus/zz_neg.go "forbidigo" <<'EOF'
package consensus

import clock "time"

var _ = clock.Now
EOF

expect "unstable sort in a pure module" lint types/zz_neg.go "forbidigo" <<'EOF'
package types

import "sort"

var _ = sort.Slice
EOF

expect "goroutine in the core" coredet consensus/zz_neg.go "go statement" <<'EOF'
package consensus

func spawn(f func()) { go f() }
EOF

expect "unannotated map range in a pure module" coredet codec/zz_neg.go "range over a map" <<'EOF'
package codec

func sum(m map[string]int) (n int) {
	for _, v := range m {
		n += v
	}
	return n
}
EOF

expect "core input log imports the write-ahead log" lint consensus/inputlog/zz_neg.go "core-boundary" <<'EOF'
package inputlog

import _ "github.com/0xmhha/wbft/consensus/wal"
EOF

expect "goroutine in the core input log" coredet consensus/inputlog/zz_neg.go "go statement" <<'EOF'
package inputlog

func spawn(f func()) { go f() }
EOF

echo "lint-negative: $pass passed, $fails failed"
[[ $fails -eq 0 ]]
