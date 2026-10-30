# Own-message evidence in R01 exports

`wbft-journal export --format r01` keeps received-frame references in
`relay_of`. An outgoing relay without a received-frame source can instead
carry `own_message_of`, naming an accepted own-message outcome of the same
writer run. That outcome has `input_of`, naming an `own_input` record.

An `own_input` preserves the original journal sequence, segment and byte
offset, core `engine_run` and `step`, internal message kind/via, self peer,
code, dedup key, payload size and content-addressed SHA-256. The exporter
requires the exact following core input to match the outcome's generation,
step, code, peer and key, and recovers the input's signature as the recording
node. Outcomes without a known generation, adapter-offer outcomes, peer and
backlog inputs, conflicting inputs, and runs with dropped records cannot
supply this evidence. Repeated accepted copies of the same own bytes leave
the outgoing relay unlinked rather than choosing one input.

This is byte provenance, not an association with a particular asynchronous
transport call. It does not prove wire delivery. A signer alone is not an
internal-input witness, and no received-frame sequence is invented.

The export indexes accepted internal inputs before writing records, because
wire writes and outcomes may precede the corresponding step record. Both
passes must read the same decoded record stream and physical positions when
own-input evidence is present. A changing journal fails the export; export a
stable retained copy or retry after the writer is quiet. A failed or damaged
export is not a completed evidence set.

The JSON format version remains 1; `own_input` is an additional record type.
Consumers must support and validate the new reference chain before using it.
Legacy journal outcomes remain readable; an absent generation stays unknown.
Consumers can validate source coordinate shape and uniqueness, payload
hashes, signatures and reference consistency. Authenticating a coordinate
against retained raw journal bytes is a separate source audit.


# Measured scheduler sources in R01 exports

A journal declaring `Core.TimerTrace = 1` exports a `scheduler_trace`
declaration, every `timer_operation` and every `scheduler_step`. An
`own_input` already represents its original step and carries entry clocks
when measured; it does not get a duplicate sequence or source coordinate.
Step entry clocks absent from old WAL replay records remain absent.

The declaration uses the first segment's raw sequence and physical position.
Its clock is explicitly `unavailable` (zero/epoch placeholders) and must not
be used as a measured time. Decimal-string version and snapshot counts let
consumers detect missing rows. Scheduler context is retained even when a
frame height range is selected, so the range does not silently remove an arm
or cancellation needed to interpret a later operation.

Operations preserve the mutex sequence, actual mono/wall clock, engine,
step, output index and original arm identity. Sequence continues across
engine lifecycles within one writer run. A callback retains its arm's cause;
a lifecycle operation can name the last completed step with output zero.
The closed timeout metadata includes kind, generation, full decimal view,
entry/deadline nanoseconds and SHA-256 of the original encoded timeout.
Full timeout bytes stay in the local journal. Cancellation requests include
kinds even when every expiry is already queued.

The snapshot is not a consensus replay or a proof of wire delivery. Consumers
must validate completeness, replay operation ordering and bind the event to
the same run, engine, step and timer identity. Source coordinate authenticity
requires a separate comparison to retained raw bytes. Both export passes
must read the identical record stream and positions; an actively changing or
damaged export is not complete evidence. Journals without the capability
preserve their previous R01 output and do not gain inferred scheduler clocks.


# Completed-write cache transition checks

`wbft-journal check-write-cache --dir DIR --max-records 100000 --max-ledgers 32 --max-reordered 256`
checks retained `accepted_completed_v1` write-ledger observations. The three
positive limits are explicit offline inspection bounds; the example is not a
node operating budget. The reader retains declaration, gap and write-cache
metadata, discarding unrelated payload records after decoding them.

The checker rebuilds pending ownership and the code-aware address/message
LRUs independently of the runtime ledger. It follows original writer runs,
ledger and request numbers, restores numbered callback order within the given
buffer bound, and distinguishes missing evidence from contradictory evidence.
It does not infer a successful write from a queue acknowledgement. Missing
profile declarations, cache gaps, missing transitions and inspection limits
produce `status: unavailable` and exit 69. Contradictions exit 1; usage or I/O
errors exit 2. Transition consistency exits 0 with `status: consistent`.

`physical_status` remains `unavailable`: this command does not yet bind the
trace to independent physical stream/write records or direct core ACCEPT
sources, and does not establish remote delivery or functional runtime replay.
The node's journal restriction and replay capability refusal remain in place.


# Accepted-receive cache transition checks

`wbft-journal check-receive-cache --dir DIR --max-records 100000 --max-ledgers 32 --max-reordered 256`
rebuilds scoped known entries, peer recent entries and independent pending
checks. Unverified pending copies do not authenticate each other. The checker
uses its own ordered-slice LRUs and compares immutable context metadata for
each original writer/scope. Missing capture or context metadata stays missing.
The supplied limits bound offline inspection; they are not node operating,
payload or heap budgets. Unrelated payload records are discarded after decode.

Both cache commands use exit 0 for transition consistency, 69 for unavailable
evidence or inspection limits, 1 for retained contradictions, and 2 for usage
or I/O errors. Receive gaps and missing operation numbers are unavailable.
A different view, state or authority digest for the same frozen scope is a
contradiction. Decimal views and counters are preserved without floating point.

`physical_status` remains `unavailable`. This command does not authenticate
context hashes against original authority history, check the actual core
step/output and signatures, or resolve captures against physical frame bytes.
Its result is not a functional runtime replay or a completed cache-policy
acceptance. The node journal restriction remains in place.


# Round-change retry source checks

`wbft-journal check-round-change-retry --dir DIR --source-limits limits.json`
checks original retry ownership, timer lifetimes, independently recomputed
core outputs, public signer state and later original own-message WAL frames.
It binds the old timer generation and unsigned signing identity separately
from the raw signed payload's cache key and SHA-256. A decision must fall
inside its original core step after signing. Repeated or mixed decisions,
non-validator targets and changed signed bytes contradict the retained source.
The completed-write path also rebuilds the original pending/recent ledger.

All inspection limits must be positive and explicit. For example:

```json
{
  "Timers": {
    "Core": {
      "Records": 100000, "Runs": 32, "Steps": 100000,
      "Environments": 400000, "Outputs": 400000, "Bytes": 67108864
    },
    "Operations": 400000, "Bindings": 400000, "Bytes": 67108864
  },
  "Signer": {
    "Lifetimes": 64, "Operations": 400000,
    "Records": 400000, "Bytes": 67108864
  },
  "Writes": { "Records": 100000, "Ledgers": 64, "Reordered": 256 }
}
```

These example values are offline inspection bounds, not operating defaults.
The limits file is capped at 64 KiB, accepts one JSON object and rejects unknown
fields. Segment decoding occurs before retained-input limits apply; this is
not a process heap or WAL disk bound. The loader caps record count; byte
inspection budgets are checked after collection by the independent checkers.
Missing declarations, owner coordinates,
original signer/WAL evidence or inspection capacity produce `unavailable`
and exit 69. Conditional consistency exits 0, contradictions exit 1, and
usage or input I/O errors exit 2. `physical_status` stays `unavailable`.
The result does not establish physical writes, remote delivery, physical
durability or functional accepted-cache replay. Legacy cache binding is not
an independent replay of its entire LRU history.

R01 cannot preserve the core/signing/WAL source chain of this mode. An input
declaring a round-change retry profile, including an unknown profile, or
containing a retry cache source is rejected before output is created. Height
filters and segment rotation cannot turn it into a legacy cache trace.
Existing disabled-mode R01 output retains its original format. Use a retained
original journal or `export --format bundle` for the new check and compatible
readers. Bundles preserve selected original segments; missing retained sources
remain unavailable and are not reconstructed from event labels.


# Scoped receive failure source checks

`wbft-journal check-receive-failures --dir DIR --source-limits limits.json`
uses the separate failure-source checker. It independently executes original
core inputs, rechecks original failed inputs in their authority context, and
rebuilds the bounded failure cache in cache-mutex sequence order. Original
inbox request and lookup references bind a reused failure to its earlier
check. A reuse contributes to `consumed_failures` and `inbox.cached_failures`,
never `inbox.checked`, a new signer call, or core acceptance.

Every inspection limit must be explicit and positive. An example is:

```json
{
  "Caches": 32,
  "Inbox": {
    "Core": {
      "Records": 100000, "Runs": 32, "Steps": 100000,
      "Environments": 400000, "Outputs": 400000, "Bytes": 67108864
    },
    "Operations": 400000, "Entries": 100000, "Peers": 256,
    "Frames": 100000, "Bytes": 67108864
  }
}
```

These values are offline examples, not operating defaults. The limits file
accepts one JSON object up to 64 KiB and rejects unknown fields. The loader
caps retained record count. Segment decoding happens before that bound and
encoded byte budgets are inspected after collection, so these limits are not
process memory, verification CPU or node storage limits.

Exit 0 means consistency within the returned finite source scope; missing
original core/frame/queue evidence, an unsupported prefix/profile, a gap or
an inspection limit produces `unavailable` and exit 69. Retained contradictions
exit 1; usage and input I/O errors exit 2. Physical and schedule reconstruction
remain unavailable. Declarations, coordinates and cache counts alone cannot
establish a real failed check or its consumption. Functional replay remains
unsupported. A configured failure cache does not disable the consensus WAL.

R01 export rejects a receive-failure declaration, including an unknown one,
or either separate failure record kind before creating output. Height filters
and segment rotation do not bypass this check. Use retained original journals
or bundles; a bundle preserves selected source segments without manufacturing
missing input evidence. This inspection command alone does not enable runtime
diagnostic production or claim an integrated consumer acceptance.


Original diagnostic bundles select heights from the encoded `CoreStepRec.Head`
without converting source observations into functional `StepRec` records.
With neither `--from` nor `--to`, export keeps every available segment and its
index, including heightless source operations before and after the steps.
Such an unbounded export may therefore retain more metadata than a bounded
range. Explicit ranges keep the original head-interval selection rules.
A journal without any recorded step head remains unavailable for height-based
bundle selection. Original bytes and record kinds are preserved; selecting a
bundle neither supplies missing evidence nor enables functional replay.

# Chain-bound round-change source profiles

Journal segment declarations carry the chain identity and canonical domain
selected by the common chain rule, including before its activation height.
Source checks bind that declaration to the recorded signer and core-step
profiles. A supported declaration remains a recorded claim; it does not
independently authenticate the genesis or establish physical persistence.

The cache, write-I/O, retry and receive-failure checks, `verify`, and `stat`
return structured `status: unavailable`, reason `unsupported_source_profile`,
and exit 69 for recognized future signer/core/domain profiles or a configured
domain whose declaration is missing. Malformed supported records and input
I/O keep their existing command contracts. `verify` still exits 1 if it has
already observed a definite contradiction before a later unsupported record;
that result does not imply that the remaining suffix was checked. `stat`
retains its existing partial-statistics and `end` behavior for ordinary damage.

R01 cannot express this domain. A streaming, read-only preflight rejects a
selected declaration or an unsupported source before own-message indexing,
legacy signature recovery, or output creation, regardless of height filters.
The indexing and output passes also check declarations. This adds a sequential
read pass with no retained source payloads; it is not an atomic snapshot of a
journal being changed concurrently. Keep the original journal or a supported
original-segment bundle. Existing legacy R01 layouts and legacy signing APIs
retain their original interpretation. Independent physical/full-runtime
restoration of the selected functional profile remains unavailable.
