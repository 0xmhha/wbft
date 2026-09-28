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
interfaces of package `app`, `validator/source`, `mempool` and `transport`.

## Status

Milestone **W0 (skeleton)**. The repository contains the package layout, the
boundary and determinism lint rules, the vector adapter speaking
`wbft-vector/1` (it answers every case `unsupported`), the traceability tool
and the CI skeleton. There is no consensus logic yet; the pure modules
(encoding, cryptography, validator sets, header rules) come next.

## Layout

Packages are listed from the bottom of the dependency order up. Lower
packages never import higher ones.

| Package | Responsibility |
|---|---|
| `crypto/keccak`, `internal/refsort`, `types` | Hashing, the reference-compatible sort, basic types and chain configuration |
| `codec/rlp`, `codec`, `crypto/ecdsa`, `crypto/bls` | Encoding, signing payloads and hashes, secp256k1 and BLS12-381 |
| `validator`, `epoch`, `validator/source`, `header` | Quorums, validator sets and proposers, epoch computation, authority source interface, header and proposal rules |
| `observe/event`, `consensus`, `consensus/inputlog` | Event vocabulary, the pure state machine, input encoding for WAL and journal |
| `wal`, `privval`, `transport`, `mempool`, `app` | Write-ahead log, private validator, transport interface and deduplication, transaction pool, application boundary |
| `consensus/runner`, `observe`, `observe/journal`, `observe/logcat`, `kv`, `participation`, `rpc` | The runtime around the core, observation, key-value store, participation records, RPC |
| `node`, `conformance/stepdriver`, `conformance/sim` | Node assembly, the step driver for vectors and traces, the deterministic simulator |
| `cmd/wbft-vector-adapter`, `cmd/wbft-replay` | Conformance vector adapter, journal replay helper |

Developer tools live in the separate module `tools/` so that their
dependencies never enter the `wbft` module graph:

| Path | Purpose |
|---|---|
| `tools/lint/coredet` | `go/analysis` analyzer for the determinism rules that linters cannot express |
| `tools/tracegen` | Builds the requirement traceability matrix |
| `internal/trace/owners.yaml` | Owner table read by `tracegen`: requirement ID to package and symbols |

## Dependencies

`wbft` may depend only on the Go standard library and these modules; CI
rejects anything else (`.golangci.yml`, `scripts/check-deps.sh`):

| Module | Used by |
|---|---|
| `github.com/ethereum/go-ethereum` v1.17.x (`rlp`, `crypto`, `common` only) | `types`, `codec/rlp`, `codec`, `crypto/keccak`, `crypto/ecdsa` |
| `github.com/supranational/blst` | `crypto/bls` |
| `github.com/holiman/uint256` | `validator/source`, `mempool` |
| `github.com/cockroachdb/pebble` | `kv` |
| `github.com/prometheus/client_golang` | `observe/metrics/prom` |
| `github.com/BurntSushi/toml` | `node` |

The go-ethereum packages `core/*`, `consensus/*`, `eth/*` and `p2p` are
forbidden. Because the go-stablenet fork has the module path
`github.com/ethereum/go-ethereum`, a build that embeds `wbft` in the fork
resolves these imports to the fork's packages; `wbft` therefore uses only
APIs present in both upstream v1.17.x and the fork, and CI builds both ways
(`.github/workflows/dual-build.yml`).

## Build, test and lint

Requirements: Go 1.24 or newer (the tools module needs Go 1.25), a C
toolchain (cgo is required from the cryptography milestone on), and
golangci-lint v2.

```sh
make build           # go build in both modules
make test            # go vet and go test in both modules
make lint            # golangci-lint, coredet and the dependency allow-list
make lint-negative   # proves the lint rules reject violating code
```

The same steps without make:

```sh
go build ./... && go vet ./... && go test ./...
go -C tools test ./...
golangci-lint run ./...
go -C tools build -o ../bin/coredet ./lint/coredet/cmd/coredet && bin/coredet ./...
scripts/check-deps.sh
```

### Lint rules

- **Boundaries** (depguard): the module allow-list above; `header` does not
  import `consensus` or `node`; the pure modules do not import `consensus`,
  `node`, `app` or the observers other than `observe/event`; `consensus` does
  not import `app`, `transport`, `privval` or `wal`; only `types` and `epoch`
  use `internal/refsort`.
- **Determinism** of the core (`consensus`, `consensus/inputlog`) and the pure
  modules (`crypto/*`, `internal/refsort`, `types`, `codec`, `codec/rlp`,
  `validator`, `epoch`, `header`), test files excepted:
  - depguard forbids `math/rand`, `crypto/rand`, `os`, `net`, `syscall` and
    `runtime` (and `sync` in the core);
  - forbidigo forbids clock calls (`time.Now`, timers, `time.Sleep`, ...),
    unstable sorts (`sort.Slice`, `sort.Sort`, `slices.SortFunc`) and
    `math.FMA`;
  - `coredet` forbids `go`, `select` and channel operations (in pure modules
    except `header.VerifyHeaders`) and requires `//wbft:unordered <reason>` on
    every direct range over a map.

## Vector adapter

`cmd/wbft-vector-adapter` runs the implementation under a conformance vector
runner using the adapter protocol `wbft-vector/1` of the specification
(A-11 §3.4): one JSON object per line on standard input and output, protocol
messages only on standard output, diagnostics on standard error.

```sh
make adapter
bin/wbft-vector-adapter -version
# Run the vectors of the specification with its reference runner:
python3 <spec-dir>/tools/vectorgen/check_adapter.py <spec-dir>/vectors -- bin/wbft-vector-adapter
```

In a conformance run all improvement items and rule flags are off and
`hello.improvements` is empty. In this milestone the adapter lists the
consensus-layer handlers in its `hello` and answers each case `unsupported`;
handlers of the execution layer are answered by the adapters of the
application repositories. The adapter exits with status 0 after `bye`, 1 when
its input ends without `bye`, and 2 on a protocol error.

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

## License

`wbft` is licensed under the GNU Lesser General Public License, version 3
or (at your option) any later version (SPDX: `LGPL-3.0-or-later`,
[LICENSE](LICENSE)). The LGPL supplements the GNU General Public License
v3.0 ([COPYING](COPYING)).
