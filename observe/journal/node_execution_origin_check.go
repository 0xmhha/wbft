package journal

import (
	"context"
	"errors"
)

// CheckRestoredNodeExecutionSourcesWithSignerOrigins retains independent Node,
// signer-origin and application verdicts. An incomplete application inspection
// never becomes an aggregate success because signing evidence was linked.
func CheckRestoredNodeExecutionSourcesWithSignerOrigins(ctx context.Context, records []Record, roots map[string]ApplicationRoot, factory ApplicationFactory, limits NodeExecutionLimits, origins *SignerOriginSources, originLimits SignerOriginLimits) (report NodeExecutionOriginCheck, checkErr error) {
	if emptySignerOrigins(origins) {
		old, err := CheckRestoredNodeExecutionSources(ctx, records, roots, factory, limits)
		return NodeExecutionOriginCheck{Status: old.Status, Reason: old.Reason, Scope: old.Scope, PhysicalStatus: old.PhysicalStatus, ScheduleStatus: old.ScheduleStatus, TerminationStatus: old.TerminationStatus, OriginStatus: "not_requested", Legacy: old, Node: old.Node, Signer: RestoredSignerOriginCheck{Status: old.Signer.Status, Reason: old.Signer.Reason, Scope: old.Signer.Scope, PhysicalStatus: old.Signer.PhysicalStatus, OriginStatus: "not_requested", Current: old.Signer, CurrentInspected: old.Signer.Status != ""}, Application: old.Application}, err
	}
	report = NodeExecutionOriginCheck{Status: "unavailable", Scope: "restored_node_sources_on_public_roots_initial_signer_and_explicit_origin_witness", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", TerminationStatus: "unavailable", OriginStatus: "unavailable"}
	b, err := newOriginBudget(originLimits)
	if err != nil {
		report.Reason = err.Error()
		return report, nil
	}
	defer func() { report.Signer.Usage = b.usage }()
	fail := func(err error) (NodeExecutionOriginCheck, error) {
		report.Reason = err.Error()
		if errorsIsOrigin(err) {
			report.Status = "inconsistent"
		}
		var limit *originLimitError
		if errors.As(err, &limit) {
			return report, nil
		}
		return report, err
	}
	// Each independently composed checker receives a fresh model. The origin
	// ledger is shared, while Node/Application retain their own typed sublimits.
	shape, err := b.shape(records)
	if err != nil {
		return fail(err)
	}
	rootShape, err := b.shape(roots)
	if err != nil {
		return fail(err)
	}
	span, err := originAdd(shape.span, rootShape.span)
	if err != nil {
		return fail(err)
	}
	if err = b.pass(span, 4096); err != nil {
		return fail(err)
	}
	report.Node, err = checkNodeSources(records, limits.Node, true)
	if err != nil {
		report.Status = report.Node.Status
		return fail(err)
	}
	if report.Node.Status != "consistent" {
		report.Reason = "node_" + report.Node.Reason
		return report, nil
	}
	_, _, _, report.Signer, err = inspectSignerOrigins(records, limits.Node.Dispatch.Receive.Core, limits.Signer, origins, b)
	report.OriginStatus = report.Signer.OriginStatus
	if err != nil {
		return fail(err)
	}
	if report.Signer.Status != "consistent_on_explicit_origin_witness" {
		report.Reason = "signer_" + report.Signer.Reason
		return report, nil
	}
	if err = b.pass(span, 4096); err != nil {
		return fail(err)
	}
	report.Application, err = CheckRestoredApplicationSources(ctx, records, roots, factory, limits.Application)
	report.Signer.Usage = b.usage
	if err != nil {
		report.Status = report.Application.Status
		return fail(err)
	}
	if report.Application.Status != "consistent_on_public_root_witness" {
		report.Reason = "application_" + report.Application.Reason
		return report, nil
	}
	report.Status = "consistent_on_public_roots_initial_signer_and_explicit_origin_witness"
	return report, nil
}
