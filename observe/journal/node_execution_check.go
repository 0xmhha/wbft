package journal

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft/consensus/privval"
)

// NodeExecutionLimits retain independent inspection bounds. The application
// factory must create isolated instances from explicit public roots; the signer
// state model uses original public initial-state witnesses, never private keys.
type NodeExecutionLimits struct {
	Node        NodeSourceLimits
	Signer      privval.SourceLimits
	Application ApplicationLimits
}

type NodeExecutionCheck struct {
	Status            string             `json:"status"`
	Reason            string             `json:"reason,omitempty"`
	Scope             string             `json:"scope"`
	PhysicalStatus    string             `json:"physical_status"`
	ScheduleStatus    string             `json:"schedule_status"`
	TerminationStatus string             `json:"termination_status"`
	Node              NodeSourceCheck    `json:"node"`
	Signer            RestoreSignerCheck `json:"signer"`
	Application       ApplicationCheck   `json:"application"`
}

// CheckNodeExecutionSources composes normal original Node sources with original
// signing calls, later original readable WAL frames and isolated application
// execution. Ordinary restored-prefix guards remain active. Every inspection
// reconstructs its own private model. Initial signer state and public application
// roots remain conditional witnesses, not authenticated physical history.
func CheckNodeExecutionSources(ctx context.Context, records []Record, roots map[string]ApplicationRoot, factory ApplicationFactory, limits NodeExecutionLimits) (NodeExecutionCheck, error) {
	report := NodeExecutionCheck{Status: "unavailable", Scope: "normal_node_sources_on_public_application_roots_and_initial_signer_witness", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", TerminationStatus: "unavailable"}
	fail := func(name, status, reason string, err error) (NodeExecutionCheck, error) {
		report.Status, report.Reason = status, name+"_"+reason
		if err != nil {
			return report, fmt.Errorf("journal: node execution %s: %w", name, err)
		}
		return report, nil
	}
	var err error
	report.Node, err = CheckNodeSources(records, limits.Node)
	if err != nil || report.Node.Status != "consistent" {
		return fail("node", report.Node.Status, report.Node.Reason, err)
	}
	report.Signer, err = checkRestoreSignerCalls(records, limits.Node.Dispatch.Receive.Core, limits.Signer)
	if err != nil || report.Signer.Status != "consistent" {
		return fail("signer", report.Signer.Status, report.Signer.Reason, err)
	}
	report.Signer.Scope = "normal_node_signer_calls_and_later_original_readable_wal"
	report.Application, err = CheckApplicationSources(ctx, records, roots, factory, limits.Application)
	if err != nil || report.Application.Status != "consistent_on_public_root_witness" {
		return fail("application", report.Application.Status, report.Application.Reason, err)
	}
	report.Status = "consistent_on_public_roots_and_initial_signer_witness"
	return report, nil
}
