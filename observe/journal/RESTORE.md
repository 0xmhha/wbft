# Restore and public signer evidence

These optional diagnostics use separate versioned journal records. They do not
enable functional cache replay, change the consensus WAL format, or synthesize
live core steps from replayed inputs.

| Kind | Source |
| --- | --- |
| 21 | Original bounded WAL readable-prefix frames and positions |
| 22 | Actual selected boundary, input indexes, replay attempts and installation |
| 23 | Initial public signer state and mutex-ordered decisions/write results |
| 24 | Actual runner signing call, core output owner and own-message WAL position |

Set `runner.Deps.WALReadSources` and positive `WALReadSourceLimits` to observe
original reads. The observer may also implement `RestoreSourceObserver` for
planning, attempt and installation records. The namespace comes from its
`CaptureRun() string` method and is frozen at construction. A Log's first
observed namespace, object-lifetime identifier and read entry sequence qualify
its reads. They do not identify an earlier unobserved writer. An original read
still executes and returns the same records, positions and error if the extra
diagnostic copy exceeds its limits.

`privval.Options.Sources` adds public-state observation to `OpenFileSigner` or
`NewKeySignerWithOptions`. The observer receives an initial logical-state
witness and the original mutex sequence of votes and floor operations. Each
record retains the original atomic-write return and the actual logical state
after the operation. Callbacks execute after unlocking and can arrive out of
order. The snapshot contains public signatures, seals and signing hashes; it
contains no private key, host filename or serialized error text. Invalid
requests rejected before entry to the signing-state mutex have no state-operation
reference. The runner call explicitly remains unavailable in that case.

`runner.Deps.SignerCalls` observes the actual core-output/signing/WAL connection.
`FileSigner.SignVoteWithSource` returns the reference frozen inside that same
operation, avoiding a later read of a concurrently changed sequence. With nil
observers, existing constructors and `SignVote` retain their original behavior.

`CheckRestoredCoreSources` independently selects and executes a readable prefix,
compares every retained replay attempt and actual installation, then supplies a
private per-engine seed to the dedicated live core inspector. The first live
step must follow the installation and use the exact next step number. The
ordinary `CheckCoreStepSources` continues to reject restored prefixes.

`CheckRestoredBoundarySources` additionally binds computed restore timers to
their actual arm owners, deadlines and timeout inputs. It compares replay-owned
internal appends with derived last-own messages and binds the first such input
through its actual pop, core step and dispatch. It does not accept all timer
lifecycle, queue or input-selection operations.

`CheckRestoredSignerSources` also checks the independent public signing-state
rules, actual request/return references, authority BLS key and signed payload.
Each selected original own-message frame requires an observed signing call and
its original WAL position in a later readable prefix of the same Log lifetime.
A supplied initial state alone does not fill missing historical signing calls.

The normal acceptance fixture uses an actual proposal and own signed messages,
graceful shutdown, restart and the first live own-vote dispatch. Observation
off/on preserves the original WAL records, stored signing state and signed
sends. Negative checks modify detached metadata only after actors and logs stop.
Failed restoration/fresh fallback and next-height restoration remain unavailable
to the integrated checker. Retaining an attempt does not establish end-to-end
coverage of every retry or failure branch.

The verdict is conditional on retained input/configuration/identity witnesses.
It establishes neither their authenticity nor historical recovery repairs,
application execution, socket I/O, physical persistence or a closed runtime
schedule. Application and physical statuses remain unavailable. Inspection
limits bound retained/indexed spans and operations in each inspection pass;
they are not allocation, heap, CPU, queue, WAL-growth or retention budgets.
Missing roots, gaps, unsupported paths and exhausted limits remain unavailable.

The default inbox/internal/receive-dispatch and functional replay guards remain
separate. These records cannot be projected into R01, including headerless
records with legacy cache declarations.


`CheckRestoredInternalSources` verifies the complete observed internal FIFO,
including its installation reset and replay-owned appends. Verified restore
arms use separate identities for each timer kind even when live step/output
coordinates are zero. `CheckRestoredTimerLifecycleSources` follows these arms
through actual queue, dequeue, replacement, cancellation and clear operations.

`CheckRestoredInboxSources` derives the initial replay snapshot from its original
WAL installation. The replay flag persists on later live publications and is
checked separately from publication phase. The first post-restore selection
uses the actual installation boundary rather than a fabricated live Start step.
Standalone inbox and selection checks still require independent evidence for
Known-message discards.

`CheckRestoredReceiveDispatchSources` verifies original raw receive sources,
checking-ledger lookups, private replay qualification and actual dispositions.
A replay marker never substitutes for required coordinates. Only successful
independent verification can supply private Known-discard evidence to queue
inspectors. The ordinary entry points retain their restored-prefix guards.

`CheckRestoredNodeSources` composes these checks with accepted writes, local I/O,
application queues and finalize tasks. `CheckRestoredNodeExecutionSources` also
checks public initial signer witnesses, actual signing/WAL bindings and isolated
application execution from explicit public roots. Each inspection reconstructs
fresh private state. No caller-supplied core model or runtime result is reused.

Additional original readable-prefix records need not have installed a restore.
They are validated and counted as `unreferenced_reads`; the checker does not
infer their purpose, close completion or durability. Every retained engine still
requires its actual installation record.

A successful composition leaves physical, schedule and termination statuses
unavailable. Retained-work counts concern checked queues only. Initial public
signer state and public application prefixes remain conditional witnesses, and
cross-lifetime WAL ownership, operational budgets and full runtime closure
require separate evidence.
