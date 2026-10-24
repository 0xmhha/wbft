package journal

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/p2p/transport"
)

type WriteAcceptedSourceLimits struct {
	Write   WriteCacheCheckLimits
	Receive ReceiveSourceLimits
}
type WriteAcceptedSourceCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	ScheduleStatus string `json:"schedule_status"`
	Registrations  uint64 `json:"registrations,string"`
}

var ErrWriteAcceptedSource = errors.New("journal: inconsistent accepted-input write source")

type acceptedReceiveRequest struct {
	run             string
	ledger, request uint64
}

// CheckWriteAcceptedSources follows the original receive request reference,
// never a peer/key search. Full runtime scheduling/replay stays unavailable.
func CheckWriteAcceptedSources(records []Record, limits WriteAcceptedSourceLimits) (WriteAcceptedSourceCheck, error) {
	return checkWriteAcceptedSources(records, limits, false)
}

func checkWriteAcceptedSources(records []Record, limits WriteAcceptedSourceLimits, restored bool) (WriteAcceptedSourceCheck, error) {
	report := WriteAcceptedSourceCheck{Status: "unavailable", Scope: "accepted_input_write_recent", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (WriteAcceptedSourceCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (WriteAcceptedSourceCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrWriteAcceptedSource, reason)
	}
	write, err := CheckWriteCacheTransitions(records, limits.Write)
	if err != nil {
		return inconsistent("write_" + write.Reason)
	}
	if write.Status != "consistent" {
		return unavailable("write_" + write.Reason)
	}
	receive, err := checkReceiveSources(records, limits.Receive, restored)
	if err != nil {
		return inconsistent("receive_" + receive.Reason)
	}
	if receive.Status != "consistent" {
		return unavailable("receive_" + receive.Reason)
	}
	accepted := map[acceptedReceiveRequest]transport.ReceiveTransition{}
	run := ""
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			run = r.Run
		case *ReceiveCacheRec:
			t := r.Transition
			if t.Action == transport.ReceiveCheckAccept && (t.Decision == transport.ReceiveRegistered || t.Decision == transport.ReceiveDuplicate) {
				key := acceptedReceiveRequest{run, t.Ledger, t.Request}
				if _, ok := accepted[key]; ok {
					return inconsistent("receive_request_registered_twice")
				}
				accepted[key] = t
			}
		}
	}
	for _, record := range records {
		w, ok := record.Body.(*WriteCacheRec)
		if !ok {
			continue
		}
		t := w.Transition
		if t.Action != transport.WriteAccept || !t.Registered {
			continue
		}
		s := t.AcceptedSource
		if s.LedgerRun == "" || s.Ledger == 0 || s.Request == 0 || s.Scope == 0 {
			return unavailable("original_receive_request_unqualified")
		}
		r, ok := accepted[acceptedReceiveRequest{s.LedgerRun, s.Ledger, s.Request}]
		if !ok {
			return unavailable("original_receive_registration_missing")
		}
		if s.Core != r.Source || s.Origin != r.Origin || s.Scope != r.Scope {
			return inconsistent("original_receive_source_changed")
		}
		if t.Input != r.Input || t.Input != r.Checked {
			return inconsistent("original_accepted_input_changed")
		}
		report.Registrations++
	}
	if report.Registrations == 0 {
		return unavailable("no_accepted_write_registrations")
	}
	report.Status = "consistent"
	return report, nil
}
