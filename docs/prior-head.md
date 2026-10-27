# Prior-head seal provenance

The optional local improvement `bind_prior_head` binds previous-height extra
seals to the adopted header's full number, hash, parent and explicit committed
round. Its validator query is `ValidatorsAt(head.Number, head.ParentHash)`.
The successor uses a separate query, `ValidatorsAt(head.Number + 1,
BlockHash(head))`; these sets can differ at a validator rotation.

The option is disabled by default. It changes neither header validity nor the
wire protocol, committee selection, fees or chain configuration. An unavailable
historical lookup leaves previous-height seal collection unavailable; it does
not substitute the successor's validators. A successful empty lookup remains
distinct from an unavailable lookup. Stored seals for another adopted header,
round or historical membership cannot occupy a current source's extra-seal slot.
Same-height prepared-state recovery keeps its existing behavior.

The runner requires WAL replay and an open WAL for this option. Its format-3
boundary wraps the exact ordinary format-1 or deferred format-2 boundary body
and records the historical query result, availability, adopted hash and round.
Ordinary and deferred-only profiles keep their previous boundary encoding.
Use a build supporting this option and its WAL profile when reopening the data
directory. A supporting build rejects a mismatched option or boundary profile;
an older build does not understand the option. Removing an option from an older
build's configuration is not a supported downgrade procedure.

New-profile steps retain validator lookup answers and their full query tuples.
The closed step driver consumes those records rather than inferring historical
availability from a canonical successor set. Context-scoped application answers
stay separate from validator authority records. Single-set vector inputs do not
provide this historical source and report the profile as unsupported.

The independent journal restore checker reconstructs an ordinary format-3
boundary from the retained original WAL read, independently of the runner's
planner. The combined deferred profile still reports its existing independent
ledger reconstruction as unavailable. Functional deferred WAL replay is tested
separately. Reconstruction is conditional on retained local application sources;
it does not prove independent chain authority, application execution, physical
durability, signer state or operational recovery time.
