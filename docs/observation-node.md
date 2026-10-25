# Explicit recent participation in a node

`node.Config.Observation` is absent by default. An explicit configuration
selects the activation boundary, positive recent-retention H, proof window k,
all consensus observation limits and local recovery/witness budgets. It changes
no candidate diligence, qualification, validator selection or fee calculation.
These parameters require agreement among operators before network activation;
no production values are supplied by the library.

The initial runtime requires `Journal.Disabled=true`. Its observation policy
is persisted separately from the functional journal and checked on every normal
restart. Removing the option or changing the policy digest refuses to start a
home with persisted observation data. This profile does not provide functional
journal replay or certify hardware power-loss durability.

## Candidate and admission paths

The builder computes the existing consensus and epoch fields first, then calls
`app.PrepareObservation`. The SDK calls this extension after execution
finalizers and before constructing the block, receipts or any hash-keyed cache.
The returned carrier is frozen before its own signatures. Commit callbacks
replace only the nested current round/certificates. Proof and observation bytes
remain unchanged, so the block identity is stable throughout sealing.

`codec.DecodeExtra` remains the strict legacy decoder. Explicit consensus
primitives use `DecodeConsensusExtra` only as a nested format view; that view
supplies no admission authority. A full header environment requires its
configured `ObservationVerifier`. It selects activation from the actual
parent's next height, checks the exact policy/version and runs the observation
transition after all existing ordered header/execution checks. A disabled full
verifier keeps legacy admission. A light verifier has no automatic V2 mode.

An application's independent full header verifier must obtain
`Node.ObservationVerifier()` and set `header.Env.Observation` when its
observation option is configured. It must refuse verification until that gate
is available. This does not replace its other header, execution or epoch rules.

## Witness intake and proof selection

The functional witness sink receives copied extra-seal entries retained by
ordinary consensus processing. It does not consume diagnostic records, create
new network messages or infer timing from signatures. Intake independently
checks historical signer membership and BLS against stored hash-bound targets.
The stored certificate supplies the uint32 round; a different full consensus
view is not inferred from that narrower field.

`witnessItems`, `witnessBytes` and `witnessChecksPerStep` explicitly bound the
local durable spool and per-step verification. Source scanning rotates through
available entries. Duplicate verified entries require no new verification.
Expired records are removed from the spool. A dropped or unavailable local
witness is an intake limitation, never proof of intentional nonparticipation.

Selection considers permitted older targets before newer ones. For each target
and phase it starts with an intact parent certificate when available, then adds
only verified individual signatures at indices absent from that certificate.
Each signer contributes once. Overlapping aggregates are never added. Proofs
are ordered by full target height and phase and bound by the policy's proof
limit. The engine verifies their canonical encoding, historical authority and
BLS before a candidate can be submitted.

## State, recovery and status

Canonical adoption recomputes the observation state and persists a bounded
checkpoint. Restart anchors that checkpoint in the application's actual head
ancestry. Checkpoint metadata supplies only a lookup hint. A trusted suffix is
replayed with full historical finality and observation checks; an ahead,
unrelated or out-of-budget checkpoint refuses observation recovery. Hash-only
ancestry is bounded by `historyWalk` and `replayHeaders`; a nearer independently
trusted checkpoint is needed when those bounds are insufficient.

A state/checkpoint failure makes observation verification/building unavailable.
Witness spool errors are exposed separately. `wbft_nodeInfo.observation`
reports the policy digest, H, activation, k, latest matured and last settled
intervals, local witness count/drops/errors and availability. These counters
are observation metadata, not economic weights or a missing-signature score.

## JSON configuration

`ObservationConfig` uses canonical decimal strings for `chainId`, `activation`
and `retention`, preserving values wider than 64 bits. Every field is required
and unknown fields are refused. Its fields are:

- `chainId`, `genesisHash`, `activation`, `retention`, `window`;
- `codec`: `extraBytes`, `proofs`, `settlementRows`, `validators`;
- `stateBytes`, `checkpointBytes`, `addressRows`;
- `historyWalk`, `replayHeaders`;
- `witnessItems`, `witnessBytes`, `witnessChecksPerStep`.

The SDK home accepts this object under `observation`. The compatibility node
accepts a file through `--wbft.observation` with `--wbft.journal=false`.
No configuration example enables a production network implicitly.
