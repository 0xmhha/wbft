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
	return checkTimerLifecycleSources(records, limits, false, restoredQueueEvidence{})
}

// CheckRestoredTimerLifecycleSources first derives restore arms from the original
// WAL. Ordinary guards remain active. Each dependent core inspection uses fresh
// private state, and verified arms never become fabricated live core outputs.
func CheckRestoredTimerLifecycleSources(records []Record, limits TimerSourceLimits) (TimerLifecycleCheck, error) {
	restore, seeds, err := reconstructRestoreSources(records, limits.Core)
	report := newTimerLifecycleCheck()
	if err != nil || restore.Status != "consistent" {
		report.Reason = "restore_not_reconstructed"
		if err != nil {
			report.Status = "inconsistent"
		}
		return report, err
	}
	var evidence restoredQueueEvidence
	effects, err := inspectRestoreEffects(records, limits.Core, seeds, func(e restoredQueueEvidence) { evidence = e })
	if err != nil || effects.Status != "consistent" {
		report.Status, report.Reason = effects.Status, "effects_"+effects.Reason
		return report, err
	}
	report, err = checkTimerLifecycleSources(records, limits, true, evidence)
	report.Scope = "scheduler_mutations_on_independent_wal_restore_and_core_sources"
	return report, err
}

func checkTimerLifecycleSources(records []Record, limits TimerSourceLimits, restored bool, evidence restoredQueueEvidence) (TimerLifecycleCheck, error) {
	base, err := checkTimerSources(records, limits, restored)
	if base.Status != "consistent" || err != nil {
		report := newTimerLifecycleCheck()
		report.Status, report.Reason = base.Status, "bindings_"+base.Reason
		if err != nil {
			return report, fmt.Errorf("%w: %w", ErrTimerLifecycleSource, err)
		}
		return report, nil
	}
	return inspectTimerLifecycleWithRestore(records, limits, evidence)
}

func newTimerLifecycleCheck() TimerLifecycleCheck {
	return TimerLifecycleCheck{Status: "unavailable", Scope: "scheduler_mutations_on_bound_core_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
}

type lifecycleArm struct {
	record *TimerRec
	kind   consensus.TimerKind
	queued bool
}

// A restored arm has no live step/output. Kind separates its original timers
// without changing the wire format or overloading a live core output identity.
type lifecycleSourceKey struct {
	timerSourceOutputKey
	restoredKind uint64
}

func timerLifecycleSourceIdentity(writer string, t *TimerRec, arm bool, kind consensus.TimerKind) lifecycleSourceKey {
	key := lifecycleSourceKey{timerSourceOutputKey: timerSourceOutputKey{timerSourceStepKey{writer, t.EngineRun, t.Step}, t.Output}}
	if arm {
		key.timerSourceOutputKey = timerSourceOutputKey{timerSourceStepKey{writer, t.ArmEngineRun, t.ArmStep}, t.ArmOutput}
		if t.ArmEngineRun != 0 && t.ArmStep == 0 && t.ArmOutput == 0 {
			key.restoredKind = uint64(kind) + 1
		}
	} else if t.Source == "restore" && t.Step == 0 && t.Output == 0 {
		key.restoredKind = uint64(kind) + 1
	}
	return key
}

func inspectTimerLifecycle(records []Record, limits TimerSourceLimits) (TimerLifecycleCheck, error) {
	return inspectTimerLifecycleWithRestore(records, limits, restoredQueueEvidence{})
}

func inspectTimerLifecycleWithRestore(records []Record, limits TimerSourceLimits, evidence restoredQueueEvidence) (TimerLifecycleCheck, error) {
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
	profiles := map[string]consensus.ImprovementSet{}
	steps := map[timerSourceStepKey]*CoreStepRec{}
	run := ""
	var count, span uint64
	for _, record := range records {
		switch t := record.Body.(type) {
		case *SegmentRec:
			run = t.Run
			options := consensus.ImprovementSet(t.Core.Improvements)
			if previous, ok := profiles[run]; ok && previous != options {
				return inconsistent("timer_profile_changed")
			}
			profiles[run] = options
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
		kinds := map[*TimerRec]consensus.TimerKind{}
		for _, t := range operations {
			for _, kind := range t.Kinds {
				if kind == uint64(consensus.ValidatorStartTimer) && !profiles[writer].Has(consensus.DeferValidatorStart) {
					return unavailable("validator_start_timer_profile_missing")
				}
			}
			if t.Source == "restore" && evidence.timers[restoredTimerSourceKey{writer, t.EngineRun, t.Sequence}] != t {
				return unavailable("timer_restoration_requires_proof")
			}
			if len(t.Input) > 0 {
				input, e := inputlog.Decode(inputlog.KindTimeout, t.Input, nil)
				timeout, ok := input.(consensus.Timeout)
				if e != nil {
					return inconsistent("timer_timeout_encoding_changed")
				}
				if !ok || timeout.Kind > consensus.ValidatorStartTimer {
					return inconsistent("timer_kind_changed")
				}
				if timeout.Kind == consensus.ValidatorStartTimer && !profiles[writer].Has(consensus.DeferValidatorStart) {
					return unavailable("validator_start_timer_profile_missing")
				}
				kinds[t] = timeout.Kind
			}
		}
		keyOf := func(t *TimerRec, arm bool) lifecycleSourceKey {
			return timerLifecycleSourceIdentity(writer, t, arm, kinds[t])
		}
		causes := map[lifecycleSourceKey]*TimerRec{}
		for _, t := range operations {

			if (t.Source == "core" || t.Source == "lifecycle" || t.Source == "restore") && (t.Action == "arm" || t.Action == "cancel") {
				key := keyOf(t, false)
				if causes[key] != nil {
					return inconsistent("timer_mutation_cause_repeated")
				}
				causes[key] = t
			}
		}
		arms := map[lifecycleSourceKey]*lifecycleArm{}
		live := map[consensus.TimerKind]lifecycleSourceKey{}
		var queue []lifecycleSourceKey
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
			kind := kinds[t]
			arm := arms[armKey]
			sameArm := arm != nil && arm.kind == kind && bytes.Equal(arm.record.Input, t.Input) && arm.record.EntryMono == t.EntryMono && arm.record.Deadline == t.Deadline
			switch t.Action {
			case "arm":
				if (t.Source != "core" && evidence.timers[restoredTimerSourceKey{writer, t.EngineRun, t.Sequence}] != t) || owner != armKey || arm != nil {
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
