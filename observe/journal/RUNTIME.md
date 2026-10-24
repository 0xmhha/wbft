# Original runtime return sources

`RuntimeRec` records original adapter loop and application shutdown boundaries.
A functional session ending does not establish that a reader, child writer, or
protocol has returned. These records keep those claims separate.

Applications opt in through `node.DiagnosticOptions.RuntimeSources` and provide
a positive `RuntimeRecords` bound. The observer is installed before the application
starts listening. Each loop freezes its observer and exact original session at
protocol entry. Callbacks run outside adapter locks. Exhausting the diagnostic
bound emits a classified gap; missing entries are unavailable and are never
reconstructed from a later functional callback.

Each entry has a writer namespace, monotonic sequence and original request. Its
return retains that identity, component, peer and session. Shutdown calls record
only `ok` or `error`; they do not copy error strings or application paths. A panic
or a call that has not returned does not produce a successful return record.

`CheckRuntimeSources` requires explicit record, operation, session and byte limits.
It independently checks original session observations, entry/return pairs, the
original core stop interval and the application profile's actual boundaries.
The standalone profile uses node, base, host, database and application returns.
The embedded profile uses node, base, stack close, child writer join and
application returns. Stack close is not replaced with fictional independent
host and database calls.

The SDK's `Adapter.WaitWriters` is called only after its owning server has stopped
admitting protocols and closed their sockets. The opted-in standalone host joins
writers before returning; the embedded application joins them after successful
stack close. This join does not close or replace an input and does not increase a
timeout. Existing default shutdown behavior remains available with the option off.

A consistent result applies to finite recorded return boundaries. It is not
an authenticated process history, remote delivery acknowledgement, operating
resource budget, scheduler reconstruction or proof of physical persistence.
Gaps, missing boundaries, unsupported profiles and failed shutdown calls remain
unavailable. Legacy message projections must explicitly refuse this record
domain without emitting a partial legacy proof.
