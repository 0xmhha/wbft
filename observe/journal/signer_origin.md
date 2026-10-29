# Explicit signing origins

A restored own WAL message can predate the current diagnostic writer. A current
writer's signing-call report does not authenticate such a message by itself.
The ordinary `CheckRestoredSignerSources` and
`CheckRestoredNodeExecutionSources` APIs retain that evidence boundary.

`CheckRestoredSignerSourcesWithOrigins` accepts an ordered predecessor chain of
original records and explicit `SignerOriginLink` values. The inspector checks
original core outputs, public signing-state transitions, actual signing calls,
and later canonical readable WAL frames. Each link names the exact previous and
current reader and signer endpoints. Reader IDs alone do not identify writers.
All frame bytes, positions and the complete read horizon must agree across a
link; payload-only matching and inferred latest reads are not supported.

Each supplied group supports one writer identity, WAL reader lifetime and signer
lifetime. Original segments may roll, and multiple engine runs are supported
when their exact restore-read requirements fit the explicit link. Cycles,
duplicate writers, ambiguous bindings and contradictory observations cannot
produce consistency. Missing sources, unsupported changes, gaps and finite
inspection limits remain unavailable.

The declared chain, genesis, local identity, mode, wire offset, complete core
options and raw configuration must be present and match. Embedded mode uses wire
offset zero; standalone mode uses `0x10`. `ConfigDigest` is an opaque declaration
compared between groups, not a computed or authenticated certificate. Actual
public signing keys and independently checked core authority remain necessary.
The final retained signer sequence must join the next lifetime's original
initial public state. This authenticates only the supplied logical handoff.

The result separates `Current` from inherited bindings. Inherited messages never
increase `Current.Calls`. `CurrentInspected` is false if a new origin preflight or
budget interruption prevented the ordinary current-only inspection from
completing. Conditional success is
`consistent_on_explicit_origin_witness`; physical persistence, filesystem
continuity, complete scheduling and actual process termination stay unavailable.
Nil or empty origins delegate to the existing API, including its original guard
and error, without applying new origin limits.

`CheckRestoredNodeExecutionSourcesWithSignerOrigins` additionally requires the
independent Node and Application source checks. It never completes an aggregate
with a zero or unavailable Application result. The nil-origin path retains the
complete legacy report and error in `Legacy`. Provider unavailability and its
original error cause are preserved.

All `SignerOriginLimits` fields are required for a nonempty origin request.
Writer, link, frame, input-byte, core and public signer-state counts accumulate
across the complete call. Work is a conservative logical inspection budget,
not a CPU, heap or wall-time guarantee. Structural preflight has depth limit 64
and does not invoke serialization methods. Let `p` be the measured byte span
plus 64 bytes per visited structural object, and `q(p) = 1 + p + p*p`.

| Inspection work | Reservation |
| --- | --- |
| Structural object or reference visit | 1, plus applicable count quotas |
| Retained byte span of length `n` | `n` bytes and `n` work |
| Additional decode or public-state entry count | `1 + 4*p` work |
| Independent core or replay pass | `16*q(p)` work |
| Public signer, Node or Application inspection pass | `4096*q(p)` work |
| Explicit raw-byte comparison | Both compared spans, plus reference visits |

Additional independent passes consume additional reservations. Quota failures
and arithmetic overflow stop inspection; unused reservations are not refunded.
Caller records and roots must remain immutable throughout the synchronous call.
The API does not provide an atomic snapshot of concurrently changing inputs.
