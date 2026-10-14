# wbft

`wbft` is a consensus-only implementation of the WBFT protocol in Go, written
from the WBFT specification. It plays the role that CometBFT (Tendermint)
plays for Cosmos applications: it runs the consensus state machine, verifies
headers and seals, keeps the validator set and epochs, signs safely across
restarts, and reports what happened, while the application behind a narrow
interface executes blocks and owns chain state.

The goals are:

- **Conformance.** Every normative requirement of Part A of the specification
  is implemented by identifiable code (`// Spec: WBFT-...` comments) and
  checked by unit tests, conformance vectors or simulations.
- **Interoperability.** In its default profile a `wbft` node keeps the wire
  format (`istanbul/100`, message RLP) and block format (Ethereum header plus
  WBFT extra data) of go-stablenet and can run in the same network as
  go-stablenet nodes.
- **Replayability.** The consensus core is a pure state machine: no clocks,
  goroutines, randomness or I/O. Recorded inputs replay to the same outputs.
- **Observability.** Consensus events, participation records and raw message
  journals are exposed for analysis instead of being discarded.

Block storage, synchronisation, devp2p, the EVM, governance and transaction
rules are not part of `wbft`; applications provide them through the
interfaces of package `app`, `chain/validator/source`, `mempool` and `p2p/transport`.

## Status

Milestone **W1 (pure modules)** is complete: `crypto/keccak`,
`crypto/ecdsa`, `crypto/bls`, `types` (heights and rounds as
arbitrary-precision integers, chain configuration and `config_at`),
`codec/rlp` and `codec` (extra data, headers, blocks, the four consensus
messages, signing payloads and hashes), `internal/refsort` (the reference
implementation's sort), `chain/validator` (quorum, proposer selection, epoch
schedule, validator-set lookup), `chain/epoch` (next-epoch computation, candidate
order, shuffle), `chain/validator/source` (authority snapshots and their
cache) and `chain/header` (proposal construction, seal writing and merging, proposal, header,
batch and light verification) pass the conformance vectors of their handlers.

Milestone **W2 (consensus core, write-ahead log, private validator, in
simulation)** covers:

- `consensus`: the pure state machine with the reference behaviour. One
  `Step` takes one input (start, stop, new head, request, message, replay,
  timer expiry) and returns the outputs to execute (messages to sign and
  send, relays, scheduled inputs, timer requests, build requests, commits,
  message outcomes, events). It reads the outside only through `Env`;
  `Vars` exposes the state variables and `Snapshot` the extra seals for
  proposal building.
- `consensus/inputlog`: the encoding of core inputs, `Env` answers and step
  outputs shared by the write-ahead log and the message journal.
- `consensus/wal`: a segmented append-only log with CRC-framed records, synced
  appends and repair of a damaged tail.
- `consensus/privval`: the signer on a go-stablenet node key file (the BLS key is
  derived from it), per-kind sign rules that refuse a second value for a
  view across restarts, and the sign floor for a node that takes over a key
  without its sign record.
- `consensus/runner`: the consensus goroutine, bounded per-peer receive
  queues with receive-check workers and a slot table, the timer scheduler
  with generations, signing and logging of own messages, the commit
  goroutine, and the replay of the write-ahead log at start.
- `p2p/transport`: the transport interface, the deduplication caches with the
  gossip target choice, and the frame verdicts `DecodeFrame`,
  `CheckOutbound` and `StoppedEngineAction` for the application adapters.
- `observe/event` and `observe/journal`: the event vocabulary with a JSON
  Lines writer, the schema of the event records
  (`observe/event/schema/events-v1.json`, JSON Schema 2020-12, which the
  simulator and the node tests check every record they write against), and
  the message journal (a store of its own with pruning by
  height and size). `cmd/wbft-journal` reports on a journal directory
  (`stat`), checks it (`verify`), prunes it (`prune`) and exports it, also
  while a node writes it: as a bundle (`export`, a tar file of the segments
  that cover a range of heights with a manifest, which the analyzer and
  `cmd/wbft-replay` read) or as the R-01 frame dump that wbft-inspector
  reads (`export --format r01`).
- `observe/metrics`: the metric registry (counters, gauges, histograms with
  labels) and its Prometheus text export, on the standard library. A node
  derives the metrics its event records carry (height and round, round
  changes, timer expiries, messages by code and outcome, dropped inbound
  messages, finalize durations, evidence), reads the pool sizes, the
  receive-queue bytes and the core's backlog (`wbft_backlog_messages`, from
  the snapshot of the last step) when gathered (`GaugeFunc`), counts sends left out
  by the recent cache (`wbft_send_suppressed_total`) and times the
  write-ahead log's fsyncs by method (`wbft_wal_fsync_seconds`, through
  `wal.Options.Now` and `Synced`), privval refusals by message code
  (`runner.Deps.Refused`) and parent snapshots missing from the authority
  cache by context (`preprepare`, `header_only`, `build`). A head announced
  before its snapshot and a PRE-PREPARE whose parent snapshot is missing
  are also HEALTH records (`snapshot_missing_at_head`,
  `snapshot_missing_at_preprepare`). Each new head's header gives the
  per-validator series `wbft_validator_seals_total{validator, type}` and
  `wbft_validator_missed_proposals_total{validator}`, always under
  `validator="total"` and per address for a set of at most 64; the event
  records give `wbft_validator_message_delay_seconds{validator, code}`,
  each source's first message of a code in a view less the round's start
  (off above 64 validators); a validator absent from the sets for more
  than two epochs loses its series (`DeleteWhere`); `Node.Metrics()`
  returns the registry for the application to serve or read.
- `observe/logcat`: log levels by module (observe.md 7.1). A node logs each
  part under a fixed module name (`node`, `consensus.round`, `mempool`, ...)
  at the level of `Config.Log` (a base level and per-module exceptions,
  `off` to `trace`); an unknown module refuses the start. A disabled call
  makes no record. The runner writes one line of the fixed message catalog
  (`logcat.EventEntry`) per event record, under `consensus.round` (round
  progress, timers, decisions; info for engine start/stop and finalized
  blocks) or `consensus.msg` (messages, outcomes, evidence); log settings
  do not change a run (`TestLogLevelsDoNotChangeRun`). The settings in force go to a `LOG_CONFIG` event and a
  log line at start and on `Node.SetLogLevels`, with the application's
  settings that name no module (`Config.LogUnmapped`, field `unmapped`); `wbft_logLevels` reads them,
  and `admin_wbftSetLogLevels` (`Node.AdminAPIs`, for IPC or an
  authenticated endpoint only) changes them. `logcat.BuildProfile` (and
  `cmd/wbft-logprofile`) gives the inspector's log profile: which line
  (message, level, module) is which event kind, for logs received without
  the event stream; its ID, `wbft@<digest>`, is `wbft_nodeInfo.logProfile`
  and `NODE_START.log_profile`.
- `conformance/stepdriver`: the driver of the steps vectors, which a
  transport adapter can reuse with its own frame stage, and `RunTrace`, which
  replays a message journal through the core (`cmd/wbft-replay`).
- `conformance/sim`: a deterministic multi-node simulator with a fake
  application and a fake transport, crash and disk faults, and a scenario
  bundle.

Nodes run the reference behaviour with two restart-safety rules: the
write-ahead log replay and the sign rules of the private validator (with
the core's guard against a second round-0 proposal, and the core's mark on
a ROUND-CHANGE whose prepared pair the bad-block rule released, which lets
the private validator sign it). Conformance vectors run
with every optional behaviour off.

Milestone **W3a (node and application interface)** is in progress:

- `app`: the application boundary: the `Application` interface with its
  optional extensions, the `Consensus` service interface, the request and
  response types and the error values.
- `node`: the node assembly. `Start` reads the application's `Info`, parses
  and checks the chain configuration, opens the write-ahead log and the sign
  state, sets the sign floor of a taken-over key (`TakeoverGuard`; without
  it a floor no signature followed is cleared, and `NODE_START.sign_floor`
  reports `set`, `kept` or `cleared`), runs the
  start-up handshake with the application head (finalizing a decided block
  again when needed), loads the authority snapshot of the head and starts the
  core at head + 1 with the restart-safety rules. A validator keeps a
  message journal in `<data dir>/journal` unless `Config.Journal.Disabled`
  is set; `cmd/wbft-replay` replays it. The node implements the
  `Consensus` service (proposal fields, epoch information, header
  verification, head and synchronisation notifications) on top of the header
  and epoch rules.
- `mempool`: the transaction pool. Validity is decided by the application's
  admission hook; the pool keeps per-sender nonce lists (executable and
  waiting), de-duplicates, bounds its size, rechecks after every new head
  before later admissions, and hands out proposals through an iterator that
  the builder reports to (skip a transaction or drop a sender). Ordering is
  a plugin; the built-in `fifo` orders senders by arrival and each sender by
  nonce. The node starts the pool when the application gives an admission
  hook and refuses an unknown ordering name.
- `rpc`: the read-only `wbft` namespace (`wbft_nodeInfo`,
  `wbft_consensusState`, `wbft_peers`) over a backend the node implements,
  and a JSON-RPC over HTTP handler for applications without an RPC server.
- `examples/kvstore`: an example application, a replicated key-value store.
  It implements the application interface (building proposals from the
  pool, executing them in proposal verification and at finalization,
  storing blocks, the authority source), announces blocks and lets a node
  that fell behind fetch them from its peers. `wbft-kvstore init` writes a
  local network and `wbft-kvstore start` runs one node with an HTTP API;
  `make devnet` (`scripts/kvstore-devnet.sh`) runs four processes, submits
  transactions, stops and restarts a node and checks that it catches up.
  Transactions are not signed: it is a development tool.
- `p2p/devnet`: a TCP transport for development networks and tests, with a
  consensus channel (through the frame stage) and an application channel.
  Peers are identified by the address they claim; it is not for production
  networks.

## Layout

Directories group packages by layer. Lower layers never import higher ones,
and the lint rules below enforce the direction.

| Layer | Directory | Packages | Responsibility |
|---|---|---|---|
| Primitives | `types`, `crypto`, `codec` | `types`, `crypto/keccak`, `crypto/ecdsa`, `crypto/bls`, `codec`, `codec/rlp` | Basic types and chain configuration, hashing, secp256k1 and BLS12-381, encoding, signing payloads and hashes |
| Chain rules | `chain` | `chain/validator`, `chain/validator/source`, `chain/epoch`, `chain/header` | Quorums, validator sets and proposers, authority source interface, epoch computation, header and proposal rules |
| Consensus | `consensus` | `consensus`, `consensus/inputlog`, `consensus/wal`, `consensus/privval`, `consensus/runner` | The pure state machine, input encoding for WAL and journal, write-ahead log, private validator, the runtime around the core |
| Network | `p2p` | `p2p/transport`, `p2p/devnet` | Transport interface, deduplication and frame verdicts for the application adapters; a development transport |
| Observation | `observe` | `observe`, `observe/event`, `observe/journal`, `observe/metrics`, `observe/logcat`, `observe/participation` | Event vocabulary, message journal, metrics, logging, participation records |
| Node | `node`, `app`, `mempool`, `rpc`, `storage` | `node`, `app`, `mempool`, `rpc`, `storage/kv` | Node assembly, application boundary, transaction pool, RPC, key-value store |
| Examples | `examples` | `examples/kvstore`, `examples/kvstore/cmd/wbft-kvstore` | An example application and its command for local networks |
| Conformance | `conformance` | `conformance/stepdriver`, `conformance/sim` | The step driver for vectors and traces, the deterministic simulator |
| Commands | `cmd` | `cmd/wbft-vector-adapter`, `cmd/wbft-replay`, `cmd/wbft-journal`, `cmd/wbft-logprofile` | Conformance vector adapter, journal replay helper, journal inspection and pruning, inspector log profile |

`internal` holds helpers that are not part of the API: `internal/refsort`
(the reference-compatible sort), `internal/fsys` (the file system interface
with an in-memory implementation), `internal/faultpoint` (fault injection
under the `wbft_faults` build tag), `internal/snetpartb` (the StableNet
execution-side header rules used by the vector adapter and `headerscan`) and
`internal/trace` (traceability data).

Developer tools live in the separate module `tools/` so that their
dependencies never enter the `wbft` module graph:

| Path | Purpose |
|---|---|
| `tools/lint/coredet` | `go/analysis` analyzer for the determinism rules that linters cannot express |
| `tools/lint/heightlow` | Analyzer for the 64-bit truncation sites of heights and rounds: every use of `RefLow64`, `RefLowInt64` or `RefLow32` carries `//wbft:low64 HH-nn` |
| `tools/tracegen` | Builds the requirement traceability matrix |
| `tools/headerscan` | Verifies the headers of a running network over JSON-RPC |
| `tools/chainfetch` | Downloads raw blocks and receipts of block ranges over JSON-RPC, for replay and development |
| `internal/trace/owners.yaml` | Owner table read by `tracegen`: requirement ID to package and symbols |
| `internal/trace/wbft-spec.ref` | Commit of wbft-spec that CI checks out |
| `internal/trace/baseline.tsv` | Committed baseline of the matrix (requirement IDs and vector handlers) that CI compares against |

## Dependencies

`wbft` may depend only on the Go standard library and these modules; CI
rejects anything else (`.golangci.yml`, `scripts/check-deps.sh`):

| Module | Used by |
|---|---|
| `github.com/ethereum/go-ethereum` v1.17.x (`rlp`, `crypto`, `common` only) | `types`, `codec/rlp`, `codec`, `crypto/keccak`, `crypto/ecdsa` |
| `github.com/supranational/blst` | `crypto/bls` |
| `github.com/holiman/uint256` | `chain/validator/source`, `chain/header`, `mempool`, the simulator's fake application |
| `github.com/cockroachdb/pebble` | `storage/kv` |
| `github.com/prometheus/client_golang` | `observe/metrics/prom` (reserved; `observe/metrics` writes the text format itself) |
| `github.com/BurntSushi/toml` | `node` |

`golang.org/x/sys` is linked as a dependency of the go-ethereum `crypto`
package only; no `wbft` package may import it. The go-ethereum packages
`core/*`, `consensus/*`, `eth/*` and `p2p` are forbidden. `wbft` is built
and tested against upstream go-ethereum v1.17.x only (`.github/workflows/ci.yml`).

## Build, test and lint

Requirements: Go 1.26.8 or newer (both modules), a C
toolchain (cgo is required: BLS12-381 through blst and the secp256k1 of
go-ethereum; a build without cgo stops with a compile error), and
golangci-lint v2.

```sh
make build           # go build in both modules
make test            # go vet and go test in both modules
make lint            # golangci-lint, coredet, heightlow and the dependency allow-list
make lint-negative   # proves the lint rules reject violating code
make sim             # simulation tests (WBFT_SIM_SEEDS seeds per scenario)
make sim-full        # the scenario bundle with 10000 seeds per scenario
make faults          # crashes at every fault point (build tag wbft_faults)
```

The same steps without make:

```sh
go build ./... && go vet ./... && go test ./...
go -C tools test ./...
golangci-lint run ./...
go -C tools build -o ../bin/coredet ./lint/coredet/cmd/coredet && bin/coredet ./...
go -C tools build -o ../bin/heightlow ./lint/heightlow/cmd/heightlow && \
  bin/heightlow -require "$(tr -d ' ' < scripts/heightlow-rows.txt | paste -sd, -)" ./...
scripts/check-deps.sh
```

### Lint rules

- **Boundaries** (depguard): the module allow-list above; `chain/header` does
  not import `consensus` or `node`; the pure modules do not import `consensus`,
  `node`, `app`, `p2p`, `storage` or the observers other than
  `observe/event`; `consensus` does not import `app`, `p2p/transport`,
  `consensus/privval` or `consensus/wal`; only `types` and `chain/epoch` use
  `internal/refsort`.
- **Determinism** of the core (`consensus`, `consensus/inputlog`) and the pure
  modules (`crypto/*`, `internal/refsort`, `types`, `codec`, `codec/rlp`,
  `chain/validator`, `chain/epoch`, `chain/header`), test files excepted:
  - depguard forbids `math/rand`, `crypto/rand`, `os`, `net`, `syscall` and
    `runtime` (and `sync` in the core);
  - forbidigo forbids clock calls (`time.Now`, timers, `time.Sleep`, ...),
    unstable sorts (`sort.Slice`, `sort.Sort`, `slices.SortFunc`) and
    `math.FMA`;
  - `coredet` forbids `go`, `select` and channel operations (in pure modules
    except `header.VerifyHeaders`) and requires `//wbft:unordered <reason>` on
    every direct range over a map.
- **Heights and rounds**: heights and rounds are arbitrary-precision
  integers; the reference implementation reads only their low 64 (or 32)
  bits at some places, and `wbft` does the same at those places.
  `heightlow` requires `//wbft:low64 HH-nn` on every use of a truncating
  accessor outside `types`, where `HH-nn` is a site label that groups the
  uses by the reference code they reproduce, and requires at least one use
  for every label listed in `scripts/heightlow-rows.txt`.

### Reference sort

`internal/refsort` holds a copy of the reference implementation's sort so
that candidate and transition orderings match it; see
`internal/refsort/testdata/gen` to regenerate the fixture.

## Vector adapter

`cmd/wbft-vector-adapter` runs the implementation under a conformance vector
runner using the adapter protocol `wbft-vector/1` of the specification
(A-11 §3.4): one JSON object per line on standard input and output, protocol
messages only on standard output, diagnostics on standard error.

```sh
make adapter
bin/wbft-vector-adapter -version
# Run the vectors of the specification with its reference runner:
python3 <wbft-spec>/spec/tools/vectorgen/check_adapter.py <wbft-spec>/spec/vectors -- bin/wbft-vector-adapter
```

In a conformance run all optional behaviour switches are off and
`hello.improvements` is empty. The adapter announces in its `hello` the
handlers it implements: `crypto/*`, `encoding/*`, `validators/*`,
`timers/*`, `state_machine/*`, `network/receive_outcome`, `header/*` and
`chain/config_at`. The steps handlers run the core through
`conformance/stepdriver` without a frame stage, so network cases whose
verdict belongs to the transport adapter (framing, the legacy code, size
limits, empty payloads) are answered `unsupported` here and by the
application's adapter there. Handlers of the execution layer are answered by
the adapters of the application repositories. The header handlers decide the execution-side steps of header
verification (uncle hash, gas limit, fork times, base fee) with a stand-in of
the application hook for the StableNet presets (`internal/snetpartb`). The adapter exits with status 0 after `bye`, 1 when
its input ends without `bye`, and 2 on a protocol error.

`conformance/stepdriver` can also run the steps cases the way a node runs
them: the core with `consensus.RestartSafety` and own messages signed by a
private validator (`Options.Improvements`, `Options.PrivVal`,
`Options.SignFloor`). `TestVectorsWithRestartSafety` checks that every
steps case then sends and records exactly the reference output, and
`TestVectorsWithSignFloor` that a node which took over its key signs
nothing at the first height.

`scripts/cross-arch-vectors.sh` runs the vectors whose results rest on
binary64 arithmetic (`validators/quorum`, `timers/round_timeout`) and writes
one line per case with the adapter's result. CI runs it on amd64 and arm64
(`determinism-cross-arch`) and fails when a case fails on either
architecture or when the two result files differ.

```sh
scripts/cross-arch-vectors.sh <wbft-spec>/spec bin/wbft-vector-adapter vectors.txt
```

## Simulation and journal replay

`conformance/sim` runs N nodes on a manual clock with the real runner,
private validator, write-ahead log and journal on an in-memory file system
that keeps only synced data across a crash. The seed determines the run:
two runs of one scenario write identical event files and journals. Every
run checks agreement, that no honest node signs two values in one view,
progress, the header rules of every stored block, and that a write-ahead
log replay never differs from the original run. Fault points (build tag
`wbft_faults`) crash a node between two durable steps.

```sh
WBFT_SIM_SEEDS=100 go test -run TestBundle ./conformance/sim/
go test -tags wbft_faults -run TestCrashAtFaultPoints ./conformance/sim/
go test -run TestReplayDeterminism ./conformance/stepdriver/
# Replay one node journal of a simulator export:
bin/wbft-replay -journal <dir>/<node> -chain <dir>/chain.rlp
# Inspect, check and prune a node's journal (JSON output):
bin/wbft-journal stat --dir <data dir>/journal
bin/wbft-journal verify --dir <data dir>/journal
bin/wbft-journal prune --dir <data dir>/journal --keep-heights 100000
# Bundle of heights 100 to 200 (two warm-up heights before), and its replay
# when it starts at the start of a writer run:
bin/wbft-journal export --dir <data dir>/journal --out node.tar --from 100 --to 200
bin/wbft-replay -journal node.tar -chain <chain.rlp>
# Explicit approximation when the bundle omits the recorded engine start:
# bin/wbft-replay -journal node.tar -chain <chain.rlp> -warmup-from 98 -compare-from 100
# R-01 frame dump (frames-<run>.jsonl and payloads/) of heights 100 to 200:
bin/wbft-journal export --dir <data dir>/journal --out <dir> --format r01 --from 100 --to 200
```

## Testnet header scan

`tools/headerscan` checks the headers of a running StableNet network with
the header rules of `wbft`. It fetches headers over JSON-RPC, one request at
a time and at most five per second, and verifies every header of the scanned
ranges with `header.VerifyHeader` (header-only mode with seal checks; the
steps that need the parent state are skipped) and with `header.VerifyLight`.
It also checks that the block hash computed by `wbft` equals the hash the
node reports. The ranges are blocks 0 to 100 and, for every fork block F
after genesis, blocks F to F + 100 (`-span`).

```sh
make headerscan
bin/headerscan -rpc https://api.test.stablenet.network
```

The built-in preset is the StableNet testnet (chain ID 8283, Boho at block
14 408 500); `-config` and `-forks` select another network. Every rejected
header is printed with its number, hash, failing step and error; the exit
status is 1 when a header is rejected. CI does not run the scan, since it
depends on a public endpoint.

## Traceability matrix

```sh
make tracegen
bin/tracegen -spec <spec-dir> -vectors <spec-dir>/vectors \
    -owners internal/trace/owners.yaml -code . -prefix WBFT- -format md
```

`tracegen` reads the requirement IDs from the specification chapters (or a
list file such as speclint output with `-requirements`), the `meta.yaml` of
every vector case, the owner table and the `// Spec:` / `// Covers:` comments
in the code, and writes one row per requirement: owner, symbols, code and test
references, vector handlers and case count. References to unknown IDs are
reported on standard error; `-strict` turns them into a failure.

### Coverage check

`-check` decides, for the chapters it names, whether every requirement that
`owners.yaml` gives to a `wbft` package (no `class`) is implemented and has
evidence. A requirement passes when

- every package in its `owner` field exists in the module,
- its `symbols` field is not empty and every symbol is declared in the
  module (`pkg.Name`, `pkg.Type.Method` or `pkg.Type.Field`, where `pkg` is
  a package name; an unqualified name is looked up in the owner packages),
- a `// Spec: ID` comment sits in a non-test file of one of its owner
  packages, and
- a vector handler that cites it is implemented by the adapter (its cases
  then run in the conformance step, which fails on any failed case), or,
  when no implemented handler cites it, a test file carries a
  `// Covers: ID` comment next to the test that checks it.

```sh
make adapter tracegen
bin/tracegen -spec <wbft-spec>/spec -vectors <wbft-spec>/spec/vectors \
    -owners internal/trace/owners.yaml -code . -prefix WBFT- -o /dev/null \
    -check A-01,A-02,A-03,A-04,A-08 -adapter bin/wbft-vector-adapter
```

Every gap is printed with its kind (`owner`, `symbols`, `code`,
`evidence`) and the exit status is 1 when there is one. CI runs the check
for chapters A-01, A-02, A-03, A-04 and A-08 after the conformance vectors.

### Baseline

`internal/trace/baseline.tsv` records two columns of the matrix: the
requirement IDs of the public specification and, for each, the sorted vector
handlers that cite it. The `traceability matrix` step of CI (enabled by the
repository variable `WBFT_SPEC_REPOSITORY`) runs `tracegen` with
`-baseline internal/trace/baseline.tsv` and fails when a requirement was
added or removed or when the handler column of a requirement changed. The
differences are printed one per line (`+` new requirement, `-` removed
requirement, `~` changed handlers with the added and removed handlers).

CI checks out the specification at the commit recorded in
`internal/trace/wbft-spec.ref`, so a change merged into wbft-spec does not
affect wbft until this file is updated. To move to a newer specification
revision, update `wbft-spec.ref`, regenerate the baseline against that
revision and commit both in one pull request:

```sh
make tracegen
bin/tracegen -spec <wbft-spec>/spec -vectors <wbft-spec>/spec/vectors \
    -owners internal/trace/owners.yaml -code . -prefix WBFT- -o /dev/null \
    -write-baseline internal/trace/baseline.tsv
git diff internal/trace/baseline.tsv
```

Review the diff of `baseline.tsv` in the pull request: every added or removed
ID and every added or removed handler should be explained by the
specification or vector change it follows. A removed handler or a
requirement that lost all its vectors is a coverage loss and needs a reason.

## License

`wbft` is licensed under the GNU Lesser General Public License, version 3
or (at your option) any later version (SPDX: `LGPL-3.0-or-later`,
[LICENSE](LICENSE)). The LGPL supplements the GNU General Public License
v3.0 ([COPYING](COPYING)).

## Chain rules

Chain-level rules come only from the genesis chain configuration's
`wbftRules.consensusRules`. The supported key is `rejectNumberJump`; a
missing or null value disables it, and a non-negative JSON integer sets
its activation height. Node profiles and local options do not override
these values. Unknown consensus or feature rule keys refuse startup.

`types.Config.Rules` reads activation using full heights. Header rules use
`parent.Number + 1`, including during proposal and batch verification.
`NODE_START`, configuration logs and `wbft_nodeInfo` expose the configured
activation heights and the rules digest.

The digest is Keccak-256 of the canonical JSON object containing
`anzeon.wbft`, `transitions` and every `wbftRules` group. Object keys are
sorted, array order is preserved, missing selected sections are null,
and numbers use an exact decimal coefficient without trailing zeroes
plus a base-ten exponent (omitted when zero). No floating-point conversion
is used; `100`, `100.0` and `1e2` have the same digest representation.
Activation values themselves must be integer tokens, not exponent notation.

Replay protocol `hello` includes the embedded WBFT module version. Simulator
journal segments use the same version resolver. A locally replaced dependency
without version metadata remains `unknown`, and a modified main module carries
a `-modified` suffix. These labels do not prove a matching clean core revision.

Trace replay refuses journal gap records instead of claiming matches across
lost inputs. Protocol errors include a bounded code: `input_gap` for missing
segment/step continuity or explicit journal loss, and `replay_error` otherwise.
Readable steps emitted before an error are only a prefix. Independent payload
completeness checks are still required when step inputs contain inline bytes.


### Received-frame replay references

Adapters implementing `transport.IOObserver` retain the observer clock's
monotonic and wall-clock endpoints around transport I/O. Writes end at the
underlying write return; reads end after consuming the payload and before
validation or queue delivery. A read interval may include waiting for a frame.
The existing callback timestamp remains unchanged. Optional journal intervals
and R-01 `io` fields are absent when the adapter did not measure them. Wall-clock
regressions are preserved. Interval overlap neither proves a clock fault nor
establishes a corrected one-way latency; clock agreement and message pairing
still need independent evidence. R-01 outgoing frames retain explicit write
results when recorded, including successful writes.

Adapters that support `transport.CaptureObserver` reserve a run-local capture
ID before `Receiver.Offer` and report it with the original received frame after
the offer. `transport.Inbound.Capture` carries only journal provenance. The
runner stores peer journal steps as `captured_message` references; the WAL
continues to store the original inline input for recovery. Legacy adapters keep
their existing inline journal steps without claiming a frame association.

The journal reader resolves references with a bounded, position-only index,
including frames recorded after their steps. Source runs, peer mappings, frame
stage delivery and message codes must agree. Missing, ambiguous or truncated
captures are refused in normal closed replay. Older journal layouts still
read; new capture metadata does not change wire or block encodings.

`wbft-replay -omit-missing-captures` (protocol
`omit_missing_captures: true`) explicitly models intentional input loss. The
missing received input is not fed to the core; its actual empty output list is
compared at the original recorded position. Each omitted step is labelled and
the protocol summary marks the run counterfactual. Invalid or ambiguous
references are not treated as intentional omissions. App answers are never
invented; an unrecorded application call reports `env_exhausted`.


### Replay execution identity

Core-step events include `engine_run` alongside their step number. The writer
run, engine generation and step identify the corresponding journal input,
including when a restarted engine reuses step numbers. Older events may omit
the engine generation and require an explicitly unambiguous association.

Trace replay loads each new writer's recorded configuration and requires its
engine start before feeding its steps. A changed configuration within the same
writer is refused. Recorded application answers are matched by call kind and
argument key within their source step; repeated answers for the same key are
consumed in recorded order and never reused. Missing answers remain failures.
Protocol steps and structured step errors include the source `writer_run`,
`engine_run` and `step`; callers do not need to parse diagnostic text.


### Recorded application answer context

The default `-answer-scope step` preserves closed replay: application responses
are consumed once by call kind and argument key from their original step.
Explicit `-answer-scope context` permits a missing local answer to be found in
other recorded steps of the same writer, engine, head number/hash and validator
context. Local original responses take precedence. Cross-step lookup refuses
conflicting original responses, including a conflict whose other response has
already been consumed. Absent answers remain `env_exhausted`; conflicts are
`env_ambiguous` and source/context changes are `env_source_mismatch`.

`stepdriver.NewAnswerPool` reads the retained source separately; `RunTrace`
validates the recorded configuration and step response fingerprint. Each replay
gets a new consumption session. Successful calls retain their original writer,
engine, step and one-based call index. The pool is bounded to one million source
records, 100000 steps, 100000 application answers and 16 MiB encoded responses.
Journal sequence gaps, duplicate coordinates and unsupported response kinds are
refused. Head lookups verify both the full number and hash, including fallbacks.

This option permits counterfactual application lookup; it does not reconstruct
unrecorded application execution or the reactions of other nodes. CLI returns 3
and protocol results mark the mode counterfactual even if all outputs match.
Hello advertises `context_answers_v1`; replay requests use `answer_scope`, steps
carry `context_answers` and `answer_sources`, and completion echoes the scope.
The validity boundary of an open-loop experiment must still be handled by its caller.

### Bounded replay warmup

Closed trace replay still requires a recorded engine start. Callers can explicitly
set `TraceOptions.Warmup` with a positive `FromHeight` and a later
`CompareFromHeight` (at most 10000 heights apart) to process a retained prefix
whose original start is absent. The first available step at `FromHeight` must
have a verified recorded head and a valid validator set. The driver starts a
fresh core there; its synthetic initial outputs are neither executed nor
reported as an original step. Backlog, prior views and unknown timer generations
are not reconstructed. Journal gaps, missing captures, discontinuous steps,
missing application answers and unavailable prefix heads still fail closed.

Every subsequent result carries `Approximate`, and approximate steps before the
comparison height also carry `Warmup`. Matching outputs alone do not establish
original reproduction. An actual recorded start restores its original timer
generations and clears the approximation marker. Available complete histories
use the normal exact path even when the fallback is configured.

`wbft-replay` accepts `-warmup-from N -compare-from M` with `-journal`. It returns
exit 3 when approximate results were emitted, separately from exact success (0),
different outputs (1) and failed/unavailable replay (2). Zero replayed steps are
not success. The `wbft-replay/1` hello advertises `bounded_warmup_v1`; clients must
check it before sending `warmup_from_height` and `compare_from_height`.
Protocol steps expose `approximate` and `warmup`, and completion reports separate
`approximate_steps` and `warmup_steps` totals. Warmup failures use
`warmup_unavailable` with structured source coordinates when available.

### External input schedule experiments

`TraceOptions.Schedule` and `wbft-replay -input-schedule FILE` apply one explicit
`drop`, `delay`, or `swap` to a recorded external input identified by writer,
engine and original step. Delay places that input after `other_step`; swap
exchanges two external inputs only when recorded wire stamps prove that both
were available before the earlier position. Inline transport timestamps with an
unknown journal clock origin cannot prove that boundary. Internal inputs and
lifecycle boundaries cannot be moved by these operations.

Source continuity is validated before altered execution. Original step and
journal sequence coordinates remain distinct from execution order and slot
coordinates. Source bytes and receipt timestamps are not rewritten. A drop
compares an actual empty output list at its original position. Reserved
self-deliveries, replays, requests and timer inputs must match outputs actually
produced by prior replayed handlers; unavailable reservations are retained as
empty positions with `reservation_unavailable` after the change. They are not
implicitly executed. Unprocessed newly reserved events remain pending at the
end of the finite input tape.

Experiments require explicit context application answers and a complete recorded
start; missing application responses remain failures. Moved inputs read the
recorded execution slot's head and actual validator context, rather than reusing
an old source-step head. No signing, sending, application execution, timer-length
change, or automatic reaction of other nodes is performed here. Changed timer
policies and open-loop validity boundaries require the caller's recorded evidence
and simulator scheduling integration. CLI returns 3 for a completed experiment
even when every output matches. Protocol hello advertises `input_schedule_v1`,
requests use `input_schedule`, steps retain `scheduled_input` source/slot fields
and `suppression_reason`, and completion echoes the experiment with
`counterfactual: true`. Scheduled source buffering is limited to one million
records, 100000 steps and 256 MiB encoded step inputs and responses.


### Shared replay clock and timer reservations

`conformance/manualclock` is the callback scheduler used by the deterministic
simulator. It orders equal deadlines by insertion order, preserves cancellation
identity, and delivers callbacks at their deadlines when advanced. It provides
the runner clock interface; time reversal, deadline overflow and reentrant
advancement are refused. `runner.TimerQueue` exposes the existing runner timer
implementation, including full timeout context, generation replacement,
cancellation before expiry, and preservation of already-queued expiries.

New live runner journal steps include a measured `StepRec.Entry` monotonic/wall
clock pair. `StepRec.Mono` remains the completion stamp. Entry time zero is a
known measurement; absence in older records and reconstructed WAL steps is
unknown. A trailing optional RLP entry field preserves the old encoding when
absent. Current readers accept both shapes; readers built before the extension
must be upgraded before consuming new steps with entry metadata.

These are the timing and scheduling prerequisites for timer-policy replay.
Recorded-input schedule experiments still use their finite recorded timer tape;
they do not yet regenerate timer inputs under changed duration parameters.


### Measured timer operation journal

New node and simulator journals declare `Core.TimerTrace = 1` in a trailing
optional segment field and include `timer` records (kind 8). Readers must be
upgraded before reading these journals. The absent capability preserves the
legacy segment encoding and does not enable timer recording. Custom writers
opt in through `TimerTraceEnabled`.

The runner measures scheduler mutations under the queue mutex. A sequence
orders equal monotonic timestamps. Records include arm/replacement, actual
cancellation, the cancellation request even when every timer has expired,
callback queue insertion, dequeue and lifecycle clear. Each arm keeps its
writer/engine/step/output cause, entry-based deadline and full encoded timeout
context. Output indices are one-based; zero identifies lifecycle, dequeue or
WAL restoration rather than an invented core output. Queued callbacks retain
the arm's original cause and never inherit the currently running step.

Operation timestamps are distinct from step entry and completion. In particular,
a callback can queue during processing before a later cancellation, and that
expiry remains available for dequeue. Sequence and full-context records allow
this ordering to be checked without choosing a guessed cancellation instant.
Timer input bytes count toward journal queue limits; loss remains explicit as
gap records. Segment rotation and journal bundles preserve the records and
capability. These observations are prerequisites for timer-policy execution,
not a claim that every journal can already be used for what-if replay.


### Timer policy experiments

`wbft-replay -journal DIR -chain FILE -answer-scope context -timer-policy POLICY`
regenerates timeout inputs from actual `ArmTimer`/`CancelTimers` outputs through
`runner.TimerQueue`. Policy JSON uses decimal string seconds, for example
`{"request_timeout_seconds":"2","max_request_timeout_seconds":"30"}`.
Unknown fields, duplicates, numeric JSON values, zero base timeout and duration
overflow are refused. The original configuration and height transitions remain
intact apart from these explicit parameters.

A complete source with measured step entry timing is required. The source must declare measured timer operation tracing; legacy operation
clocks remain unavailable. The untouched
baseline must reproduce outputs and timer contexts before any experiment step
is emitted. Internal `Schedule` inputs are regenerated in runner FIFO order.
Recorded signing results can be reused only for identical full Broadcast requests,
writer/engine/head context and recorded signing order; nested signatures remain
unchanged. Missing or conflicting signing results and new application questions
stop execution. This does not execute a new signer or block builder.

The explicit execution model is `recorded-external-slots/zero-generated-processing/recorded-signing-results/1`.
External processing slots and their recorded busy intervals are fixed. Generated
handlers have zero modeled processing cost. Recorded wall anchors are used at
source slots, with monotonic extrapolation between them. These are conditional
open-loop assumptions, not proof of physical execution or another node's response.
All experiment results remain counterfactual, including identical policy values.
The finite source horizon is preserved and remaining outputs are not run beyond it.

Hello advertises `timed_inputs_v1`. Use `timed_replay` with `timer_policy` and
`answer_scope:"context"`; partial ranges, missing-input omission, warmup, input
schedule combinations and vars are refused. Replies use `timed_step` and
`timed_done`. Execution/source coordinates, monotonic nanoseconds and policy
seconds are decimal strings. Generated inputs have no source step; timer arm,
causal execution parent and reused signing evidence are distinct fields. Errors
retain execution and available source/causal coordinates. CLI exits 3 for a
finished experiment and 2 for a refused or incomplete run. These experiments
still need analyzer storage, UI and explicit open-loop validity boundaries.

The baseline uses measured arm/cancel operation times and observed callback
queue times through the official scheduler. Complete operation sequence,
source-output joins, FIFO dequeue and full timeout contexts are validated before
emitting results. Missing or conflicting timing evidence is refused. Changed
policy execution uses the deterministic clock and ordinary FIFO Pop. Reused
application questions require complete output and writer/engine/head/validator
context identity; original question source and output index remain explicit.
Completion reports each writer horizon and pending internal, queued and armed
timers. A recorded Stop applies its measured runtime cleanup; no future tail is
manufactured.

Timed replay helpers declare `timed_state_v1` and return `execution_state`
from the core snapshot after each execution slot. Height and round are decimal
strings while the core runs; a stopped core returns null for both. Suppressed
original internal slots report the unchanged execution state, never the source
input view. This state is counterfactual metadata, not a canonical chain fact.

Timed helpers declaring `timed_actions_v1` return `output_actions` and
`recorded_output_actions` independently. Every action retains its one-based
output index and SHA256 of the complete encoded output. Network descriptors
separate unsigned broadcast requests, recorded signing results/failures and
actual relay bytes. Signing evidence points to both the original producer
output and its later signing input. Application build/commit requests retain
exact original-question locations and full decimal-string views; no payload,
signature or block hash is exported. Eligible recipients describe validator
membership intent, not observed transmission or delivery.

`parent_output` identifies the precise parent execution output that reserved a
regenerated input, including a broadcast awaiting unrecorded signing results.
Generated executions have no invented original output slot. A changed timer
fingerprint does not imply changed network bytes. No action descriptor proves
an arrival time or establishes other nodes' counterfactual reactions.
