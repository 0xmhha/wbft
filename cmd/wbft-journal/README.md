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
