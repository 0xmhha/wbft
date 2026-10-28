# Verified previous seals

`verify_merged_prev_seals` is a default-off local proposal assembly option.
Set it in `node.Config.Improvements` to verify the assembled previous Prepared
and Committed aggregates before returning a proposal. Applications can select
the same name in their local node configuration. It can be used independently
or together with `bind_prior_head`.

The check resolves the proposal's actual parent by `ParentHash`, uses that
parent's header round, and obtains the sealing validators from the parent's
height and ancestry. Prepared and Committed aggregates are checked separately.
If an assembled aggregate does not verify, its original parent aggregate is
used only after it verifies in that same context. An unavailable historical
validator set or an invalid original aggregate makes proposal assembly return
an error. No stored parent or supplied aggregate is rewritten.

The header builder exposes the same behavior as
`header.ProposalInputs.VerifyMergedPrevSeals`. The other reserved header
options keep their existing unsupported behavior. `header.MergeSeals` retains
its original aggregation API; callers of that function alone do not acquire a
verification step.

This option adds signature verification work to proposal construction. It
changes neither block encoding nor vote signing data, header validity rules,
or the default restart-safety profile. Runtime startup, node information and
journal metadata retain the selected name or mask. Core step replay preserves
that declaration but does not reexecute application header construction;
matching recorded core outputs alone does not prove proposal assembly or
complete physical runtime reconstruction.
