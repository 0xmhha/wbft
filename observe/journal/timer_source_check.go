package journal

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

// TimerSourceLimits bound retained inspection metadata and encoded spans, not
// WAL decoding allocations or process heap. Every limit is required.
type TimerSourceLimits struct {
	Core                        CoreSourceLimits
	Operations, Bindings, Bytes uint64
}

// TimerSourceCheck links scheduler arm/cancel operations to independently
// recomputed core outputs, and popped timeouts to actual core inputs. Other
// mutations, timer eligibility/selection, application and restoration remain
// unverified. Consistent is not complete scheduling or physical execution proof.
type TimerSourceCheck struct {
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	Scope           string `json:"scope"`
	PhysicalStatus  string `json:"physical_status"`
	ScheduleStatus  string `json:"schedule_status"`
	Arms            uint64 `json:"arm_bindings,string"`
	Cancels         uint64 `json:"cancel_bindings,string"`
	Timeouts        uint64 `json:"timeout_input_bindings,string"`
	OtherOperations uint64 `json:"other_operations_unverified,string"`
}

var ErrTimerSource = errors.New("journal: inconsistent core timer source")

type timerSourceStepKey struct {
	run          string
	engine, step uint64
}
type timerSourceOutputKey struct {
	timerSourceStepKey
	output uint64
}
type timerSourceExpected struct {
	action   string
	input    []byte
	kinds    []uint64
	entry    time.Duration
	duration time.Duration
	seen     bool
}

func CheckTimerSources(records []Record, limits TimerSourceLimits) (TimerSourceCheck, error) {
	report := TimerSourceCheck{Status: "unavailable", Scope: "core_timer_output_and_timeout_bindings", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (TimerSourceCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (TimerSourceCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrTimerSource, reason)
	}
	if limits.Operations == 0 || limits.Bindings == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	outputs := map[timerSourceOutputKey]*timerSourceExpected{}
	inputs := map[timerSourceStepKey]*timerSourceExpected{}
	steps := map[timerSourceStepKey]bool{}
	var bindings, usedBytes uint64
	captureIssue := ""
	charge := func(n uint64) bool {
		if bindings >= limits.Bindings || n > limits.Bytes-usedBytes {
			captureIssue = "timer_binding_limit"
			return false
		}
		bindings++
		usedBytes += n
		return true
	}
	core, _, err := inspectCoreSourceOutputs(records, limits.Core, func(run string, source *CoreStepRec, recomputed []consensus.Output) {
		if captureIssue != "" {
			return
		}
		key := timerSourceStepKey{run, source.EngineRun, source.Step}
		steps[key] = true
		if source.InputKind == inputlog.KindTimeout && charge(uint64(len(source.Input))) {
			inputs[key] = &timerSourceExpected{action: "pop", input: bytes.Clone(source.Input)}
		}
		for index, output := range recomputed {
			proof := &timerSourceExpected{entry: time.Duration(source.Entry.Mono)}
			switch o := output.(type) {
			case consensus.ArmTimer:
				proof.action, proof.duration = "arm", o.Duration
				var e error
				proof.input, e = inputlog.Encode(consensus.Timeout{Kind: o.Kind, View: o.View, Round: o.Round, Gen: o.Gen, Msg: o.Msg})
				if e != nil {
					captureIssue = "timer_output_encoding"
					return
				}
			case consensus.CancelTimers:
				proof.action = "cancel"
				for _, kind := range o.Kinds {
					proof.kinds = append(proof.kinds, uint64(kind))
				}
			default:
				continue
			}
			if !charge(uint64(len(proof.input)) + uint64(len(proof.kinds))*8) {
				return
			}
			outputs[timerSourceOutputKey{key, uint64(index + 1)}] = proof
		}
	})
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	if captureIssue != "" {
		return unavailable(captureIssue)
	}
	declared := map[string]uint64{}
	sequences := map[string]map[uint64]bool{}
	maximum := map[string]uint64{}
	run := ""
	var operations uint64
	for _, record := range records {
		switch t := record.Body.(type) {
		case *SegmentRec:
			run = t.Run
			if previous, known := declared[run]; known && previous != t.Core.TimerTrace {
				return inconsistent("timer_declaration_changed")
			}
			declared[run] = t.Core.TimerTrace
		case *GapRec:
			if t.Dropped > 0 && len(t.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, kind := range t.ByKind {
				if kind.Count > 0 && (kind.Kind == 0 || kind.Kind == uint64(KindTimer)) {
					return unavailable("timer_source_gap")
				}
			}
		case *TimerRec:
			if operations >= limits.Operations {
				return unavailable("timer_operation_limit")
			}
			operations++
			if run == "" || declared[run] != TimerTraceVersion {
				return unavailable("timer_trace_not_declared")
			}
			if !validTimerRec(t) {
				return inconsistent("invalid_timer_source_shape")
			}
			if sequences[run] == nil {
				sequences[run] = map[uint64]bool{}
			}
			if sequences[run][t.Sequence] {
				return inconsistent("timer_sequence_repeated")
			}
			sequences[run][t.Sequence] = true
			maximum[run] = max(maximum[run], t.Sequence)
			key := timerSourceStepKey{run, t.EngineRun, t.Step}
			var proof *timerSourceExpected
			if t.Source == "core" && (t.Action == "arm" || t.Action == "cancel") {
				proof = outputs[timerSourceOutputKey{key, t.Output}]
				if proof == nil {
					if steps[key] {
						return inconsistent("timer_core_output_reference_changed")
					}
					return unavailable("timer_core_output_missing")
				}
				if proof.action != t.Action {
					return inconsistent("timer_core_output_kind_changed")
				}
			} else if t.Source == "dequeue" && t.Action == "pop" {
				proof = inputs[key]
				if proof == nil {
					if steps[key] {
						return inconsistent("timer_core_input_reference_changed")
					}
					return unavailable("timer_core_input_missing")
				}
			} else {
				report.OtherOperations++
				continue
			}
			if proof.seen {
				return inconsistent("timer_binding_repeated")
			}
			if !bytes.Equal(t.Input, proof.input) || !slices.Equal(t.Kinds, proof.kinds) {
				return inconsistent("timer_core_value_changed")
			}
			switch t.Action {
			case "arm":
				if proof.duration > 0 && int64(proof.entry) > math.MaxInt64-int64(proof.duration) || proof.duration < 0 && int64(proof.entry) < math.MinInt64-int64(proof.duration) {
					return unavailable("timer_deadline_range")
				}
				if t.EntryMono != proof.entry || t.Deadline != proof.entry+proof.duration || t.ArmEngineRun != t.EngineRun || t.ArmStep != t.Step || t.ArmOutput != t.Output {
					return inconsistent("timer_arm_source_changed")
				}
				report.Arms++
			case "cancel":
				report.Cancels++
			case "pop":
				if t.Output != 0 {
					return inconsistent("timer_input_output_reference_changed")
				}
				report.Timeouts++
			}
			proof.seen = true
		}
	}
	for name, seen := range sequences {
		if uint64(len(seen)) != maximum[name] {
			return unavailable("timer_sequence_gap")
		}
	}
	for _, proof := range outputs {
		if !proof.seen {
			return unavailable("timer_core_output_unobserved")
		}
	}
	for _, proof := range inputs {
		if !proof.seen {
			return unavailable("timer_core_input_unobserved")
		}
	}
	if report.Arms+report.Cancels+report.Timeouts == 0 {
		return unavailable("no_core_timer_bindings")
	}
	report.Status = "consistent"
	return report, nil
}
