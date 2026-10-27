package journal

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

// AppQueueLimits bound retained inspection indexes and encoded spans, not
// decoding allocations, process heap or the runtime queue's operating budget.
type AppQueueLimits struct {
	Core                       CoreSourceLimits
	Operations, Entries, Bytes uint64
}

type AppQueueCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	ScheduleStatus string `json:"schedule_status"`
	Appended       uint64 `json:"appended,string"`
	Coalesced      uint64 `json:"coalesced,string"`
	Popped         uint64 `json:"popped,string"`
	Clears         uint64 `json:"clears,string"`
	Closes         uint64 `json:"closes,omitempty,string"`
	ClearedInputs  uint64 `json:"cleared_inputs,string"`
	Retained       uint64 `json:"retained,string"`
}

var ErrAppQueueSource = errors.New("journal: inconsistent application queue source")

type appCoreKey struct {
	writer       string
	engine, step uint64
}

// CheckAppQueueSources compares the original mutex sequence with actual core
// inputs after independently executing the core. It does not execute an app,
// validate inbox/commit queues, restore WAL state or prove a closed schedule.
func CheckAppQueueSources(records []Record, limits AppQueueLimits) (AppQueueCheck, error) {
	return checkAppQueueSources(records, limits, false)
}

func checkAppQueueSources(records []Record, limits AppQueueLimits, restored bool) (AppQueueCheck, error) {
	report := AppQueueCheck{Status: "unavailable", Scope: "application_input_queue_on_bound_core_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (AppQueueCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (AppQueueCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrAppQueueSource, reason)
	}
	if limits.Operations == 0 || limits.Entries == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	steps := map[appCoreKey]*CoreStepRec{}
	wanted := map[appCoreKey]bool{}
	stops := map[appCoreKey]bool{}
	lastSteps := map[string]*CoreStepRec{}
	base, _, err := inspectApplicationCoreOutputs(records, limits.Core, restored, func(writer string, source *CoreStepRec, _ []consensus.Output) {
		key := appCoreKey{writer, source.EngineRun, source.Step}
		steps[key] = source
		last := lastSteps[writer]
		if last == nil || source.EngineRun > last.EngineRun || source.EngineRun == last.EngineRun && source.Step > last.Step {
			lastSteps[writer] = source
		}
		if source.Via == "app" {
			wanted[key] = false
		}
		if source.InputKind == inputlog.KindStop {
			stops[key] = false
		}
	})
	if err != nil {
		return inconsistent("core_" + base.Reason)
	}
	if base.Status != "consistent" {
		return unavailable("core_" + base.Reason)
	}
	groups := map[string][]*AppQueueRec{}
	writer := ""
	var operations, span uint64
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, kind := range r.ByKind {
				if kind.Count > 0 && (kind.Kind == 0 || kind.Kind == uint64(KindAppQueue)) {
					return unavailable("application_queue_source_gap")
				}
			}
		case *AppQueueRec:
			if operations >= limits.Operations {
				return unavailable("application_queue_operation_limit")
			}
			if r.Version != AppQueueSourceVersion && r.Version != AppQueueCloseSourceVersion {
				return unavailable("application_queue_version")
			}
			if !validAppQueueRec(r) {
				return inconsistent("invalid_application_queue_source")
			}
			if r.Unavailable != "" {
				return unavailable("application_queue_" + r.Unavailable)
			}
			n := uint64(len(r.Input))
			if n > limits.Bytes-span {
				return unavailable("application_queue_byte_limit")
			}
			if writer == "" {
				return unavailable("application_queue_writer_missing")
			}
			operations++
			span += n
			groups[writer] = append(groups[writer], r)
		}
	}
	if operations == 0 {
		return unavailable("no_application_queue_sources")
	}
	nilHead, _ := inputlog.Encode(consensus.NewHead{})
	writers := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before validation
		writers = append(writers, name)
	}
	slices.Sort(writers)
	for _, name := range writers {
		items := groups[name]
		slices.SortFunc(items, func(a, b *AppQueueRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		var queue []*AppQueueRec
		var head []byte
		headPresent := false
		closed := false
		var previous uint64
		var mono time.Duration
		for _, r := range items {
			if closed {
				return inconsistent("application_queue_mutation_after_close")
			}
			if r.Sequence == previous {
				return inconsistent("application_queue_sequence_repeated")
			}
			if r.Sequence != previous+1 {
				return unavailable("application_queue_sequence_gap")
			}
			if r.Mono < mono || r.Before != uint64(len(queue)) {
				return inconsistent("application_queue_state_changed")
			}
			previous, mono = r.Sequence, r.Mono
			var decoded consensus.Input
			if r.Action != "clear" && r.Action != "close" {
				decoded, err = inputlog.Decode(r.InputKind, r.Input, nil)
				if err != nil {
					return inconsistent("application_queue_input_encoding")
				}
				canonical, err := inputlog.Encode(decoded)
				if err != nil || !bytes.Equal(canonical, r.Input) {
					return inconsistent("application_queue_input_encoding")
				}
			}
			switch r.Action {
			case "append":
				if uint64(len(queue)) >= limits.Entries {
					return unavailable("application_queue_entry_limit")
				}
				if h, ok := decoded.(consensus.NewHead); ok {
					if headPresent {
						return inconsistent("application_queue_coalesce_missing")
					}
					head, headPresent = r.Input, h.Header != nil
				}
				queue = append(queue, r)
				report.Appended++
			case "coalesce":
				var first uint64
				for _, q := range queue {
					if q.InputKind == inputlog.KindNewHead {
						first = q.Request
						break
					}
				}
				h, ok := decoded.(consensus.NewHead)
				if !ok || !headPresent || first == 0 || first != r.Request {
					return inconsistent("application_queue_coalesce_owner_changed")
				}
				head, headPresent = r.Input, h.Header != nil
				report.Coalesced++
			case "pop":
				if len(queue) == 0 || queue[0].Request != r.Request || queue[0].InputKind != r.InputKind {
					return inconsistent("application_queue_fifo_changed")
				}
				expected := queue[0].Input
				if r.InputKind == inputlog.KindNewHead {
					expected = head
					if expected == nil {
						expected = nilHead
					}
					head, headPresent = nil, false
				}
				if !bytes.Equal(expected, r.Input) {
					return inconsistent("application_queue_input_changed")
				}
				key := appCoreKey{name, r.EngineRun, r.Step}
				step := steps[key]
				if step == nil {
					return unavailable("application_queue_core_step_missing")
				}
				seen, required := wanted[key]
				if !required || seen || step.InputKind != r.InputKind || !bytes.Equal(step.Input, r.Input) || r.Mono > time.Duration(step.Entry.Mono) {
					return inconsistent("application_queue_dispatch_source_changed")
				}
				wanted[key] = true
				queue = queue[1:]
				report.Popped++
			case "close":
				key := appCoreKey{name, r.EngineRun, r.Step}
				step := steps[key]
				if step == nil {
					return unavailable("application_queue_close_stop_missing")
				}
				if step != lastSteps[name] || step.InputKind != inputlog.KindStop || !stops[key] || r.Mono < time.Duration(step.Observed.Mono) {
					return inconsistent("application_queue_close_stop_changed")
				}
				report.ClearedInputs += uint64(len(queue))
				queue, head, headPresent = nil, nil, false
				closed = true
				report.Closes++
			case "clear":
				key := appCoreKey{name, r.EngineRun, r.Step}
				step := steps[key]
				if step == nil {
					return unavailable("application_queue_stop_source_missing")
				}
				if step.InputKind != inputlog.KindStop || stops[key] || r.Mono < time.Duration(step.Observed.Mono) {
					return inconsistent("application_queue_stop_source_changed")
				}
				stops[key] = true
				report.ClearedInputs += uint64(len(queue))
				queue, head, headPresent = nil, nil, false
				report.Clears++
			}
			if r.After != uint64(len(queue)) {
				return inconsistent("application_queue_result_count_changed")
			}
		}
		report.Retained += uint64(len(queue))
	}
	for _, seen := range wanted { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("application_queue_core_input_unobserved")
		}
	}
	for _, seen := range stops { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("application_queue_stop_unobserved")
		}
	}
	report.Status = "consistent"
	return report, nil
}
