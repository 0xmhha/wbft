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

// TimerLifecycleCheck validates retained scheduler mutations after independent
// core output/input binding. It does not prove callback selection, application
// execution, WAL restoration, wall clocks or a complete runtime schedule.
type TimerLifecycleCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	ScheduleStatus string `json:"schedule_status"`
	Arms           uint64 `json:"arms,string"`
	Replacements   uint64 `json:"replacements,string"`
	Cancellations  uint64 `json:"cancellations,string"`
	Queued         uint64 `json:"queued,string"`
	Popped         uint64 `json:"popped,string"`
	Clears         uint64 `json:"clears,string"`
	RetainedLive   uint64 `json:"retained_live,string"`
	RetainedQueued uint64 `json:"retained_queued,string"`
}

var ErrTimerLifecycleSource = errors.New("journal: inconsistent timer lifecycle source")

// CheckTimerLifecycleSources uses original per-writer mutex sequences, which
// may arrive out of order at a detached observer. Limits bound inspected input
// spans and indexes, not decoding allocations or process resources. A retained
// finite horizon may end with live/queued timers; those counts are explicit.
func CheckTimerLifecycleSources(records []Record, limits TimerSourceLimits) (TimerLifecycleCheck, error) {
	base, err := CheckTimerSources(records, limits)
	if base.Status != "consistent" || err != nil {
		report := newTimerLifecycleCheck()
		report.Status, report.Reason = base.Status, "bindings_"+base.Reason
		if err != nil {
			return report, fmt.Errorf("%w: %w", ErrTimerLifecycleSource, err)
		}
		return report, nil
	}
	return inspectTimerLifecycle(records, limits)
}

func newTimerLifecycleCheck() TimerLifecycleCheck {
	return TimerLifecycleCheck{Status: "unavailable", Scope: "scheduler_mutations_on_bound_core_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
}

type lifecycleArm struct {
	record *TimerRec
	kind   consensus.TimerKind
	queued bool
}

func inspectTimerLifecycle(records []Record, limits TimerSourceLimits) (TimerLifecycleCheck, error) {
	report := newTimerLifecycleCheck()
	unavailable := func(reason string) (TimerLifecycleCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (TimerLifecycleCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrTimerLifecycleSource, reason)
	}
	if limits.Operations == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	groups := map[string][]*TimerRec{}
	steps := map[timerSourceStepKey]*CoreStepRec{}
	run := ""
	var count, span uint64
	for _, record := range records {
		switch t := record.Body.(type) {
		case *SegmentRec:
			run = t.Run
		case *CoreStepRec:
			steps[timerSourceStepKey{run, t.EngineRun, t.Step}] = t
		case *TimerRec:
			if count >= limits.Operations {
				return unavailable("timer_operation_limit")
			}
			if !validTimerRec(t) {
				return inconsistent("invalid_timer_source_shape")
			}
			n := uint64(len(t.Input)) + uint64(len(t.Kinds))*8
			if n > limits.Bytes-span {
				return unavailable("timer_lifecycle_byte_limit")
			}
			if run == "" {
				return unavailable("timer_writer_missing")
			}
			count++
			span += n
			groups[run] = append(groups[run], t)
		}
	}
	if count == 0 {
		return unavailable("no_timer_mutations")
	}
	writers := make([]string, 0, len(groups))
	for writer := range groups { //wbft:unordered sorted before validation
		writers = append(writers, writer)
	}
	slices.Sort(writers)
	for _, writer := range writers {
		operations := groups[writer]
		slices.SortFunc(operations, func(a, b *TimerRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		keyOf := func(t *TimerRec, arm bool) timerSourceOutputKey {
			if arm {
				return timerSourceOutputKey{timerSourceStepKey{writer, t.ArmEngineRun, t.ArmStep}, t.ArmOutput}
			}
			return timerSourceOutputKey{timerSourceStepKey{writer, t.EngineRun, t.Step}, t.Output}
		}
		causes := map[timerSourceOutputKey]*TimerRec{}
		for _, t := range operations {
			if t.Source == "restore" {
				return unavailable("timer_restoration_requires_proof")
			}
			if (t.Source == "core" || t.Source == "lifecycle") && (t.Action == "arm" || t.Action == "cancel") {
				key := keyOf(t, false)
				if causes[key] != nil {
					return inconsistent("timer_mutation_cause_repeated")
				}
				causes[key] = t
			}
		}
		arms := map[timerSourceOutputKey]*lifecycleArm{}
		live := map[consensus.TimerKind]timerSourceOutputKey{}
		var queue []timerSourceOutputKey
		var previous uint64
		var mono time.Duration
		for _, t := range operations {
			if t.Sequence == previous {
				return inconsistent("timer_sequence_repeated")
			}
			if t.Sequence != previous+1 {
				return unavailable("timer_sequence_gap")
			}
			if t.Mono < mono {
				return inconsistent("timer_monotonic_order_changed")
			}
			previous, mono = t.Sequence, t.Mono
			owner, armKey := keyOf(t, false), keyOf(t, true)
			step := steps[owner.timerSourceStepKey]
			if t.Source == "core" && (t.Action == "arm" || t.Action == "cancel" || t.Action == "replace" || t.Action == "cancelled") {
				if step == nil {
					return unavailable("timer_mutation_step_missing")
				}
				if t.Output == 0 || t.Mono < time.Duration(step.Entry.Mono) || t.Mono > time.Duration(step.Observed.Mono) {
					return inconsistent("timer_mutation_outside_core_step")
				}
			}
			if t.Source == "lifecycle" {
				if step == nil {
					return unavailable("timer_stop_source_missing")
				}
				if step.InputKind != inputlog.KindStop || t.Output != 0 || t.Mono < time.Duration(step.Observed.Mono) {
					return inconsistent("timer_stop_source_changed")
				}
			}
			var kind consensus.TimerKind
			if len(t.Input) != 0 {
				input, err := inputlog.Decode(inputlog.KindTimeout, t.Input, nil)
				if err != nil {
					return inconsistent("timer_timeout_encoding_changed")
				}
				timeout, ok := input.(consensus.Timeout)
				if !ok || timeout.Kind > consensus.RoundProposalTimer {
					return inconsistent("timer_kind_changed")
				}
				kind = timeout.Kind
			}
			arm := arms[armKey]
			sameArm := arm != nil && arm.kind == kind && bytes.Equal(arm.record.Input, t.Input) && arm.record.EntryMono == t.EntryMono && arm.record.Deadline == t.Deadline
			switch t.Action {
			case "arm":
				if t.Source != "core" || owner != armKey || arm != nil {
					return inconsistent("timer_arm_identity_changed")
				}
				if _, exists := live[kind]; exists {
					return inconsistent("timer_replacement_missing")
				}
				arms[armKey] = &lifecycleArm{record: t, kind: kind}
				live[kind] = armKey
				report.Arms++
			case "replace", "cancelled":
				current, exists := live[kind]
				cause := causes[owner]
				if !sameArm || !exists || current != armKey || cause == nil || cause.Source != t.Source || cause.Sequence <= t.Sequence {
					return inconsistent("timer_retirement_source_changed")
				}
				if t.Action == "replace" {
					if t.Source != "core" || cause.Action != "arm" || cause.Sequence != t.Sequence+1 {
						return inconsistent("timer_replacement_cause_changed")
					}
					input, err := inputlog.Decode(inputlog.KindTimeout, cause.Input, nil)
					next, ok := input.(consensus.Timeout)
					if err != nil || !ok || next.Kind != kind {
						return inconsistent("timer_replacement_kind_changed")
					}
					report.Replacements++
				} else {
					if cause.Action != "cancel" || !slices.Contains(cause.Kinds, uint64(kind)) {
						return inconsistent("timer_cancellation_cause_changed")
					}
					report.Cancellations++
				}
				delete(live, kind)
			case "queued":
				current, exists := live[kind]
				if !sameArm || !exists || current != armKey || owner != armKey || t.Source != arm.record.Source || arm.queued || t.Mono < t.Deadline {
					return inconsistent("timer_queue_source_changed")
				}
				arm.queued = true
				delete(live, kind)
				queue = append(queue, armKey)
				report.Queued++
			case "pop":
				if !sameArm || !arm.queued || t.Source != "dequeue" || t.Output != 0 || len(queue) == 0 || queue[0] != armKey {
					return inconsistent("timer_dequeue_order_changed")
				}
				if step == nil {
					return unavailable("timer_timeout_step_missing")
				}
				if step.InputKind != inputlog.KindTimeout || !bytes.Equal(step.Input, t.Input) || t.Mono > time.Duration(step.Entry.Mono) {
					return inconsistent("timer_dequeue_input_changed")
				}
				queue = queue[1:]
				arm.queued = false
				report.Popped++
			case "cancel":
				if t.Source != "core" && t.Source != "lifecycle" {
					return inconsistent("timer_cancel_source_changed")
				}
				for _, k := range t.Kinds {
					if _, exists := live[consensus.TimerKind(k)]; exists {
						return inconsistent("timer_cancellation_missing")
					}
				}
			case "clear":
				cause := causes[owner]
				if t.Source != "lifecycle" || cause == nil || cause.Action != "cancel" || cause.Source != "lifecycle" || cause.Sequence >= t.Sequence || len(live) != 0 {
					return inconsistent("timer_clear_source_changed")
				}
				queue = nil
				report.Clears++
			default:
				return inconsistent("timer_operation_changed")
			}
		}
		report.RetainedLive += uint64(len(live))
		report.RetainedQueued += uint64(len(queue))
	}
	report.Status = "consistent"
	return report, nil
}
