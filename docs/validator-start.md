# Validator startup availability

`defer_validator_start` is an experimental, default-off local improvement. It
defers entry into a new consensus height when its validator lookup returns an
error or no set. A valid non-nil empty set remains a successful lookup. No block,
message, signature or consensus-hash format changes.

Select it explicitly in `node.Config.Improvements`, or in
`runner.Config.Core.Improvements`. Pending entry retains the exact target height,
parent, requested round and continuation. It does not partially adopt a new
height or expose the retained old validator set as production authority.
`Snapshot.ValidatorStart` describes the wait; the pending production snapshot
has `Running=false`. Ordinary inputs cannot produce votes or builds while
waiting. A local `validator_start` timer retries after one second. Stale
callbacks cannot resume another target. Exhausted generations arm no timer.

The existing three- and four-counter APIs keep their shapes. The selected
`TimerGenerations` profile contains five counters; slot 3 is zero unless round
proposal validation is also enabled. Selected restoration requires the complete
five-counter profile and rejects rollback. It never silently restores a partial
legacy counter array.

## Finite functional history

With a WAL, the selection requires replay and an automatic WAL `Header` callback
of nil. Fresh logs begin with a synchronous format-5 seed before the first
timer, builder notification or snapshot. Existing nonempty legacy logs cannot
be migrated automatically. Updated readers reject a format-5 history with the
selection disabled, replay disabled or different effective configuration before
returning application-handshake actions.

`node.Config.ValidatorHistory` and `runner.Config.ValidatorHistory` optionally
override `runner.ValidatorHistoryLimits`. Both `Bytes` and `Records` must be
positive and at most `MaxInt64`; nil selects **64 MiB and 65,536 records**. The
values are frozen into the seed. Too-small limits can refuse startup before any
output. The byte count includes each functional frame's body and ten framing
bytes, including input, environment answers, own votes or refusals, commits,
deferred records and controls. It excludes other journals, signer/application
files, filesystem allocation, heap and CPU costs.

This profile retains the original seed and its complete dependent prefix within
the cap instead of pruning it by `KeepHeights`. Every Step reserves its complete
supported recording budget before signing, requesting a build or handing over a
commit. Its input, ordered answers and intent are synchronized before those
effects; a synchronized completion binds the actual outputs. The supported own
message bound covers the builtin signer's 65-byte ECDSA signature and at most a
96-byte BLS seal. An unmatched signing intent cannot become a completed Step.

The cap includes a dedicated 1,024-byte, one-record terminal reserve. Exhaustion
halts progress while preserving the history and attempts one bounded terminal
sync. Normal progress also consumes this finite budget. It is not an uptime
recommendation. Increasing limits, disabling the selection or discarding an
unfinished tail is not a supported way to resume the same history. Migration or
a separately validated checkpoint procedure would be needed. A storage sync
failure does not provide an independent physical-durability guarantee.

## Recovery and observation scope

Recovery validates the original full prefix, its seed/configuration, ordered
answers, cumulative usage, input/output ownership, exact timer generations and
completion boundaries. It rejects incomplete Steps and terminal histories.
Seed-only histories are meaningful. A newer application canonical head is
recorded as a live catchup input before installing restored effects; conflicting
or older heads are refused. Higher canonical heads use the existing application
trust boundary, without an independent ancestry proof.

A pending restored state installs only its current retry. A ready state uses
the existing current-view own-message policy and may reissue only its actual,
still-unsatisfied current build request. Historical outputs and physical peer,
application or worker queues are not replayed wholesale. A plain lifecycle Stop
is not a functional input that would turn the restored state into a stopped core.

Pure steps-vector `stepdriver.Run` inputs cannot represent ordered validator
lookup availability and reject this selection as unsupported. This restriction
does not disable closed journal replay.

Fresh journal traces support the selected ordered authority answers and actual
pre-Start five-counter record. Raw `StepRec.Env` cannot distinguish nil from
empty member BLS keys; selected ambiguous traces require the missing key witness
and return unsupported. Core source observations and format-5 witnesses retain
that presence mask separately. The existing independent restore-observation
model does not implement format 5 and reports `validator_start_profile`
unavailable, including when it detects the format in original read frames.
This does not claim complete runtime, signer, application or physical recovery.

Without a WAL, only live deferral is available when other selected options allow
that configuration. The default-off behavior, legacy record bytes and retention
policy remain unchanged. Historical binaries that skip unknown formats are not
supported downgrade readers for this profile.
