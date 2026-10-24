package journal

import "fmt"

// NodeSourceLimits retain the bounds of each independent inspection. They do
// not configure live queues, execution time, process memory or WAL retention.
type NodeSourceLimits struct {
	Dispatch ReceiveDispatchLimits
	Write    WriteCacheCheckLimits
	IO       WriteIOCheckLimits
	Finalize FinalizeLimits
}

// NodeSourceCheck composes original normal Node sources. Known-input discard
// evidence is private, reconstructed from the original lookup/core sources and
// consumed explicitly. Standalone inbox/selection guards remain unchanged.
// QueueHorizonStatus counts retained work only in the explicitly checked queues;
// it does not certify a runtime termination boundary or absent future callbacks.
// Successful composition is not complete runtime replay or physical proof.
type NodeSourceCheck struct {
	Status             string                   `json:"status"`
	Reason             string                   `json:"reason,omitempty"`
	Scope              string                   `json:"scope"`
	PhysicalStatus     string                   `json:"physical_status"`
	ScheduleStatus     string                   `json:"schedule_status"`
	SignerStatus       string                   `json:"signer_status"`
	ApplicationStatus  string                   `json:"application_status"`
	TerminationStatus  string                   `json:"termination_status"`
	QueueHorizonStatus string                   `json:"queue_horizon_status"`
	SourceEnds         NodeSourceEnds           `json:"source_ends"`
	Internal           InternalCheck            `json:"internal"`
	App                AppQueueCheck            `json:"app_queue"`
	Dispatch           ReceiveDispatchCheck     `json:"dispatch"`
	Inbox              InboxCheck               `json:"inbox"`
	Selection          SelectionCheck           `json:"selection"`
	AcceptedWrite      WriteAcceptedSourceCheck `json:"accepted_write"`
	IO                 WriteIOCheck             `json:"local_io"`
	Finalize           FinalizeCheck            `json:"finalize"`
	Timers             TimerLifecycleCheck      `json:"timers"`
}

func CheckNodeSources(records []Record, limits NodeSourceLimits) (NodeSourceCheck, error) {
	report := NodeSourceCheck{Status: "unavailable", Scope: "original_node_dispatch_queue_and_local_io_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", SignerStatus: "unavailable", ApplicationStatus: "unavailable", TerminationStatus: "unavailable", QueueHorizonStatus: "unavailable"}
	result := func(name, status, reason string, err error) (NodeSourceCheck, error) {
		report.Status, report.Reason = status, name+"_"+reason
		if err != nil {
			return report, fmt.Errorf("journal: node source %s: %w", name, err)
		}
		return report, nil
	}
	var discarded receiveDiscardEvidenceSet
	var err error
	report.Dispatch, err = checkReceiveDispatchSources(records, limits.Dispatch, func(e receiveDiscardEvidenceSet) { discarded = e })
	if err != nil || report.Dispatch.Status != "consistent" {
		return result("dispatch", report.Dispatch.Status, report.Dispatch.Reason, err)
	}
	// Each inspection creates its own state. No runtime mutation, caller
	// certificate, erased unavailable marker or invented core step is used.
	report.Internal, err = CheckInternalSources(records, limits.Dispatch.Selections.Internal)
	if err != nil || report.Internal.Status != "consistent" {
		return result("internal", report.Internal.Status, report.Internal.Reason, err)
	}
	report.App, err = CheckAppQueueSources(records, limits.Finalize.Queue)
	if err != nil || report.App.Status != "consistent" {
		return result("app_queue", report.App.Status, report.App.Reason, err)
	}
	report.Inbox, err = checkInboxSources(records, limits.Dispatch.Selections.Inbox, discarded)
	if err != nil || report.Inbox.Status != "consistent" {
		return result("inbox", report.Inbox.Status, report.Inbox.Reason, err)
	}
	report.Selection, err = checkInputSelections(records, limits.Dispatch.Selections, discarded)
	if err != nil || report.Selection.Status != "consistent" {
		return result("selection", report.Selection.Status, report.Selection.Reason, err)
	}
	report.AcceptedWrite, err = CheckWriteAcceptedSources(records, WriteAcceptedSourceLimits{Write: limits.Write, Receive: limits.Dispatch.Receive})
	if err != nil || report.AcceptedWrite.Status != "consistent" {
		return result("accepted_write", report.AcceptedWrite.Status, report.AcceptedWrite.Reason, err)
	}
	report.IO, err = CheckWriteIOSources(records, limits.IO)
	if err != nil || report.IO.Status != "consistent" {
		return result("local_io", report.IO.Status, report.IO.Reason, err)
	}
	report.Finalize, err = CheckFinalizeSources(records, limits.Finalize)
	if err != nil || report.Finalize.Status != "consistent" {
		return result("finalize", report.Finalize.Status, report.Finalize.Reason, err)
	}
	report.Timers, err = CheckTimerLifecycleSources(records, limits.Dispatch.Selections.Timer)
	if err != nil || report.Timers.Status != "consistent" {
		return result("timer", report.Timers.Status, report.Timers.Reason, err)
	}
	report.SourceEnds = inspectNodeSourceEnds(records)
	report.Status, report.Reason = "consistent", ""
	report.QueueHorizonStatus = "retained_work"
	if report.Internal.RetainedQueued == 0 && report.Internal.RetainedTaken == 0 && report.App.Retained == 0 && report.Dispatch.RetainedPreparations == 0 && report.Inbox.RetainedQueued == 0 && report.Inbox.RetainedChecking == 0 && report.Inbox.RetainedSlots == 0 && report.Inbox.RetainedTaken == 0 && report.Selection.RetainedSelected == 0 && report.Finalize.RetainedQueued == 0 && report.Finalize.RetainedActive == 0 && report.Finalize.RetainedReturned == 0 && report.Timers.RetainedLive == 0 && report.Timers.RetainedQueued == 0 {
		report.QueueHorizonStatus = "no_retained_work_in_checked_queues"
	}
	return report, nil
}
