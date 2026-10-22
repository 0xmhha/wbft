# Simulated write service

This package provides a single-threaded FIFO stream for manual-clock experiments.
One active write is separate from an explicit positive waiting-entry capacity.
Admission owns a copy of the original bytes. Each admitted request receives one
terminal callback; a refusal receives none. Normal stream close cancels pending
writes, preserves completed receipts and suppresses remaining stream arrivals.
Reconnection always creates a new functional session.

Local completion occurs after declared write service. Arrival follows a separate
declared link delay. These are simulated events, not measured socket operations
or proof of remote acceptance. Durations exceeding the representable clock
horizon never become early completion. Entry capacity does not bound payload
bytes, in-flight arrivals, journal allocation or process heap.

The consensus simulator opts in through `NodeSpec.WriteQueue`; the default
adapter and its artifacts retain their original behavior. The optional adapter
uses scenario link delay after FIFO write service and records outgoing messages
at simulated completion. Its startup event declares `write_queue_model` and the
unchanged legacy cache policy. This model accepts normal, lossless scenarios
and ordinary stop/restart actions. It does not select completed-write caches,
enable functional cache replay or reconstruct physical execution. Analyzer
runtime fitting refuses this declaration until an explicit model supports it.

`NodeSpec.AcceptedCache` is a separate diagnostic experiment requiring explicit
`Journal: sim.CacheDiagnosticOnly`, positive cache limits and write queues on
all endpoints. It connects accepted-input and completed-write ledgers to an
independent diagnostic writer, using original receiver-side streams and capture
origins. The functional runner journal stays nil. Session, cache and detached
core-source records support independent comparisons on retained inputs; socket
I/O timing stays absent. Unsupported functional replay, physical reconstruction
and complete scheduling proof remain unavailable. Restored WAL prefixes need
their own source reconstruction before they can satisfy those broader claims.
