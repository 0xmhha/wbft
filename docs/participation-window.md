# Explicit participation observations

`codec/window`, `chain/window` and `observe/window` provide an explicit
observation format, deterministic settlement and anchored checkpoint storage.
They do not enable a node fork or change legacy decoding, candidate diligence,
validator selection or fees. They supply no production activation height.

A valid historical prepare or commit signature included in a permitted carrier
is an observation. It does not attest signature creation or receipt time.
Absence from carriers does not prove intentional nonparticipation.

## Format and transition

The envelope is `[2, legacy, proofs, observation]`. `legacy` stays a nested
ten-item list. Neither codec silently falls back to another format.

Each proof is `[height, hash, round, authorityDigest, phase, bitmap, signature]`.
Proofs use increasing `(height, phase)` order with one entry per key per carrier.
Bitmaps use historical signer indices without trailing zero bytes. Heights and
counts are full non-negative integers; the existing round field is uint32.
The authority digest commits indexed address/key tuples in actual order.

Every block's observation is
`[1, policyDigest, parentStateRoot, resultStateRoot, settlement]`. Settlement is
an empty list outside an epoch. At an epoch it is
`[1, previousSettledThrough, nextSettledThrough, deltaRows]`. An address-sorted
row is `[address, eligiblePrepare, eligibleCommit, observedPrepare, observedCommit]`.
These counts are not diligence or reward weights.

State commits policy, carrier height, parent hash, settled/matured cursors,
cumulative counts, matured pending counts and open targets. Open targets retain
hash, final round, indexed historical authority and phase bitmap unions. The
state excludes its own carrier hash, avoiding a circular commitment. Its root
uses the `WBFT-PARTICIPATION-STATE/1` domain.

For window `k`, target `h` can appear in carriers `h+1` through `h+k`. Its final
round comes from its successor's hash-bound `PrevRound`. An epoch first settles
only the parent's matured counts, through at most `n-1-k`. The current proofs
are verified and unioned, then targets through `n-k` mature into pending counts.
The current carrier cannot change that same block's settlement. Repeated
signatures count once per historical signer and phase. Earlier-than-activation
targets receive no opportunities.

### Recent matured-target retention

`NewRecent(config, H)` explicitly selects a separate policy with positive H.
No production H or activation height is supplied. The policy digest binds H
and all existing limits. Existing `New(config)` keeps its cumulative format,
state roots and checkpoints unchanged; the two modes cannot share checkpoints.

Recent mode uses observation version 2 and a complete epoch snapshot:
`[2, previousSettledThrough, nextSettledThrough, from, replacementRows]`.
Rows replace the previous snapshot rather than adding signed deltas. The
snapshot covers at most H eligible matured targets ending at the parent's
settled cursor. The current carrier's newly matured target cannot affect that
same epoch snapshot. `SettledWindow()` labels `Counts(address)` with this
published interval. `RecentWindow()` and `RecentCounts(address)` separately
describe the latest matured interval, which can be ahead of that settlement.

After maturity, each retained target holds only its full height, historical
addresses and prepare/commit bitmap unions. Historical public keys and
certificates are discarded from this observation state. Targets older than
the latest H matured targets are evicted immediately. An address whose
eligible targets have expired has no retained history; rejoining does not
restore its old observations. This is not evidence of failed participation.

State and checkpoint version 2 commit the recent interval and the last
published snapshot. Both are bounded by H and the explicit byte/row limits.
The open proof interval remains bounded by k. Retention does not delete the
application's canonical headers, authenticated history or block archive.
Increasing H can exhaust explicit capacity and must be measured before use.

### Read-only observation bands

`Engine.DiagnoseRecent(state, address, view, policy)` reads either the complete
`settled` snapshot or the independently labelled `recent_preview` snapshot.
`BandPolicy` requires a positive minimum number of eligible targets, at most H,
and an explicit inclusive rational threshold in (0, 1]. Each phase must meet
that threshold separately; a high prepare count cannot hide a low commit count.
Exact integer products avoid rounded percentages and uint64 product overflow.

Zero opportunities produce `NO_HISTORY`; a positive count below the minimum
produces `INSUFFICIENT_HISTORY`. Both have a null `observed_band`. Sufficient
history produces `IN_OBSERVED_BAND` or `BELOW_OBSERVED_BAND`. These are inclusion
observations, not evidence of deliberate nonparticipation or blacklist status.
Invalid policy, unavailable state and cumulative mode remain errors.

The result carries full decimal integers, a normalized threshold, the selected
interval, carrier identity, state root and observation policy digest. These
identities do not authenticate a caller-provided checkpoint: the caller still
supplies authenticated history or an independently trusted anchor. External
adapters must bound requests and keep unverified models distinct from verified
chain observations. This library method does not expose an RPC or UI, enable a
network policy, change state, or produce diligence, validator sets or fee weights.

The filtered hash changes only the nested current round and current prepare
and commit certificates. Proofs, settlement and state roots remain hash-bound.
`Build` refuses candidates with current certificates; the caller must freeze
proof selection before preparing a proposal. Subset observations do not relax
finality quorum requirements.

## Explicit caller integration

Create `chain/window.Engine` with a `Config`. Chain identity, activation
boundary, window and every structural/state/checkpoint limit bind its `Digest()`.
There are no default network settings. `Initial` needs a caller-trusted parent
immediately before the boundary.

Supply `History.Header(hash, fullHeight)` and `History.Authority(target)` from
authenticated history. Authority must use unique addresses in historical signer
order and registered keys. The engine checks header identity, parent continuity,
historical commitments, signer ranges and BLS subset signatures. The provider
remains responsible for canonical adoption, key ownership, epoch schedule and
finality. An untrusted snapshot or truncated-height lookup is unsuitable.

`Build` returns a separate explicit carrier and immutable state, preserving
legacy epoch information including diligence. It does not sign or submit the
carrier. `Apply` recomputes its observation transition and compares the complete
canonical commitment. Failure leaves the parent unchanged. Ordinary node and
application paths keep their existing format until a separate integration
explicitly enables these carriers.

`NewBranchHistory(engine, chain, config, maxWalk)` supplies a bounded adapter
for an application's authenticated `types.ChainReader`. It snapshots the epoch
schedule, checks the configured genesis identity and follows only parent hashes
at full heights. It never substitutes a canonical height index for the target's
branch. The governing epoch supplies signer order and keys. `maxWalk` bounds
each authority lookup and has no default; `ErrLookupLimit` means local history
or budget is insufficient, not that a block or signer failed. The application
still authenticates epoch transitions, registered key ownership and adoption.

`VerifyFinality` separately verifies current prepare/commit quorum certificates
and the carrier's prepare/commit certificates for its parent. Each target uses
its governing historical authority; genesis has no parent certificate check.
The first explicit carrier can verify a legacy parent's signing domain.
`VerifyAndApply` performs these checks before the observation transition and
leaves its parent state unchanged on failure. Neither method replaces header,
execution, epoch or canonical-chain verification. `Apply` remains available to
callers that already verified finality through their own block verifier.

`State.Counts(address)` returns copied settled cumulative counts. False means
no settled eligible history; pending/open observations are not failed scores.
Economic lookback, qualification, rejoining and rewards remain separate policies.

## Checkpoints and capacity

A checkpoint is `[1, carrierHeight, carrierHash, state]`. `EncodeCheckpoint` and
`Recover` need an independently trusted carrier and compare policy, height,
parent lineage and state root. A file's own hash cannot supply a trust anchor.
A recovered state verifies the next suffix with the same history and transition.

`observe/window.Save` writes in an existing caller-owned directory, syncs the
file, renames it and syncs the directory. Serialize saves to one path. `Load`
bounds reads and verifies the checkpoint against the trusted carrier. These
calls do not certify hardware power-loss durability.

Config requires extra bytes, proof count, signer ceiling, settlement rows, state
bytes, checkpoint bytes and address rows. Capacity exhaustion returns an
observation error without partial advancement. Expose that error rather than
turning it into a legacy block rejection or missing-signature score.

The post-carrier open set has at most `k-1` targets. This does not bound lifetime
disk use: cumulative address history and authenticated headers can grow.
Production limits, retention, epoch growth and witness intake need operating
measurements. Local witness queues require separate item, byte and verification
budgets. Do not add overlapping aggregate signatures. Select an intact verified
aggregate or aggregate distinct individual signatures. Lost constructor data
does not prove a signer was absent.
