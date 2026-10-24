# Conditional application execution sources

`node.Deps.Diagnostics` installs an optional caller-owned source writer for the
explicit accepted/completed cache policy. It requires a matching, unique
`Config.RunID`, positive WAL/signer/application copy limits, an observed write
transport, and a disabled functional journal. The caller closes the writer after
`Node.Stop`. These observations do not enable compatible functional replay.
Defaults and the ordinary journal recorder remain unchanged.

The node forwards the original live core, timer, queue, selection, dispatch,
WAL-read, restore and public signer observations. It creates the signer observer
before the initial public state and takeover-floor operation. Diagnostic copy
limits do not bound the original WAL read, signing work, execution time, process
heap or the writer's storage; configure those resources separately.

An optional `runner.SourceFinalizer` receives the immutable original commit task
coordinates. `app.FinalizeRequest.Source` carries that value across the node's
application bridge. The ordinary application contract and cancellation context
are preserved. Handshake and unobserved calls have no source owner; manual
finalizers retain their existing completion contract.

Kind 25, version 1 (`ApplicationRec`), records the canonical original Commit
arguments before the call, its interval, and the actual response hash and
idempotence flag. Errors are represented by a class only. A response is not
evidence that transactions were independently executed or physically persisted.
`ApplicationRec.Commit` decodes an owned canonical request. Legacy R01 exports
refuse this domain, including legacy cache declarations zero and one.

`CheckApplicationSources` binds these records to independently reconstructed
core outputs, original finalize tasks and application-queue notifications. A
caller separately supplies a public genesis or parent witness and an
`ApplicationFactory`. The factory must open a separate instance and storage,
execute original transactions through normal validation and finalization, and
return the independently computed header. Original application instances, DB
handles, built-result caches and observed responses are not calculation inputs.
A parent witness may instead supply bounded original public prefix blocks, all
of which the provider must execute from its independent genesis instance.

Provider implementations belong to the application. The generic checker cannot
establish their correctness. A missing witness/provider, unsupported profile,
failed or unfinished call, missing evidence, classified loss or inspection limit
leaves the result unavailable. No error string, node home or secret key is part
of this journal contract. Applications must allowlist public root-witness fields.

`CheckRestoredApplicationSources` is the explicit restored-prefix path. It first
reconstructs the original readable WAL prefix and installed core, then verifies
restore effects when a restored prefix exists. Each dependent queue/finalize
inspection builds fresh private seeds; mutable model state and caller-issued
certificates are not shared. Ordinary source checkers keep their restore guard.
A restored timer callback retains its original arm owner. Its retained expiry
is bound to the verified arm's input, owner, sequence and deadline, separately
from the installation-time arm. This is not a complete scheduler lifecycle proof.

Success is `consistent_on_public_root_witness`. It is conditional on the supplied
public initial state, configuration, authority history and provider. Physical
durability, complete network/runtime scheduling and operational resource budgets
remain separate acceptance requirements.
