package stepdriver

import (
	"bytes"
	"time"

	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/journal"
)

type observedArmKey struct {
	writer               string
	engine, step, output uint64
}
type observedArm struct {
	operation *journal.TimerRec
	queued    *journal.TimerRec
}
type observedTimers struct {
	operations map[observedArmKey]*journal.TimerRec
	byStep     map[answerCoordinate][]observedArmKey
	arms       map[observedArmKey]*observedArm
	pops       map[answerCoordinate]*journal.TimerRec
	records    map[string][]*journal.TimerRec
	lifecycle  map[answerCoordinate][]*journal.TimerRec
}

func newObservedTimers() *observedTimers {
	return &observedTimers{operations: map[observedArmKey]*journal.TimerRec{}, byStep: map[answerCoordinate][]observedArmKey{}, arms: map[observedArmKey]*observedArm{}, pops: map[answerCoordinate]*journal.TimerRec{}, records: map[string][]*journal.TimerRec{}, lifecycle: map[answerCoordinate][]*journal.TimerRec{}}
}
func (t *observedTimers) validate(entries []timedSourceEntry) error {
	steps := map[answerCoordinate]*journal.StepRec{}
	profiles := map[answerCoordinate]consensus.ImprovementSet{}
	for _, entry := range entries {
		if entry.config.TimerTrace != journal.TimerTraceVersion {
			return ErrTraceTiming
		}
		steps[answerCoordinate{entry.source.Writer, entry.source.Engine, entry.source.Step}] = entry.record
		profiles[answerCoordinate{entry.source.Writer, entry.source.Engine, entry.source.Step}] = consensus.ImprovementSet(entry.config.Improvements)
	}
	for writer, records := range t.records {
		var sequence uint64
		var mono time.Duration
		live := map[uint8]observedArmKey{}
		var pending []observedArmKey
		for _, r := range records {
			if r.Sequence != sequence+1 || r.Mono < mono {
				return ErrTraceTiming
			}
			sequence = r.Sequence
			mono = r.Mono
			key := observedArmKey{writer, r.ArmEngineRun, r.ArmStep, r.ArmOutput}
			owner := observedArmKey{writer, r.EngineRun, r.Step, r.Output}
			var timeout consensus.Timeout
			if len(r.Input) > 0 {
				in, err := inputlog.Decode(inputlog.KindTimeout, r.Input, nil)
				if err != nil {
					return ErrTraceInvalidInput
				}
				var ok bool
				timeout, ok = in.(consensus.Timeout)
				if !ok || timeout.Kind > consensus.ValidatorStartTimer {
					return ErrTraceInvalidInput
				}
				mask := profiles[answerCoordinate{writer, r.ArmEngineRun, r.ArmStep}]
				if timeout.Kind == consensus.ValidatorStartTimer && !mask.Has(consensus.DeferValidatorStart) || timeout.Kind == consensus.RoundProposalTimer && !mask.Has(consensus.ValidateRoundProposals) {
					return ErrTraceConfiguration
				}
			}
			for _, kind := range r.Kinds {
				if kind == uint64(consensus.ValidatorStartTimer) && !profiles[answerCoordinate{writer, r.EngineRun, r.Step}].Has(consensus.DeferValidatorStart) {
					return ErrTraceConfiguration
				}
			}
			if r.Source == "core" && (r.Action == "arm" || r.Action == "cancel") {
				step := steps[answerCoordinate{writer, r.EngineRun, r.Step}]
				if step == nil || step.Entry == nil || r.Output == 0 || r.Mono < step.Entry.Mono || r.Mono > step.Mono {
					return ErrTraceTiming
				}
				if _, exists := t.operations[owner]; exists {
					return ErrTraceTiming
				}
				t.operations[owner] = r
				where := answerCoordinate{writer, r.EngineRun, r.Step}
				t.byStep[where] = append(t.byStep[where], owner)
			}
			if r.Source == "lifecycle" {
				where := answerCoordinate{writer, r.EngineRun, r.Step}
				step := steps[where]
				if step == nil || step.InputKind != inputlog.KindStop || r.Output != 0 || r.Mono < step.Mono {
					return ErrTraceTiming
				}
				t.lifecycle[where] = append(t.lifecycle[where], r)
			}
			switch r.Action {
			case "arm":
				// Restoration needs a separate state reconstruction proof; never turn
				// a WAL operation with unknown entry into a live source input.
				if r.Source != "core" || owner != key || r.EntryMono != steps[answerCoordinate{writer, r.EngineRun, r.Step}].Entry.Mono {
					return ErrTraceTiming
				}
				if _, exists := t.arms[key]; exists {
					return ErrTraceTiming
				}
				if _, exists := live[uint8(timeout.Kind)]; exists {
					return ErrTraceTiming
				}
				t.arms[key] = &observedArm{operation: r}
				live[uint8(timeout.Kind)] = key
			case "replace", "cancelled":
				if r.Source != "core" {
					return ErrTraceTiming
				}
				arm := t.arms[key]
				if arm == nil || live[uint8(timeout.Kind)] != key || !sameObservedArm(arm.operation, r) {
					return ErrTraceTiming
				}
				delete(live, uint8(timeout.Kind))
			case "queued":
				arm := t.arms[key]
				if arm == nil || owner != key || r.Source != arm.operation.Source || live[uint8(timeout.Kind)] != key || arm.queued != nil || !sameObservedArm(arm.operation, r) || r.Mono < r.Deadline {
					return ErrTraceTiming
				}
				arm.queued = r
				delete(live, uint8(timeout.Kind))
				pending = append(pending, key)
			case "pop":
				arm := t.arms[key]
				if arm == nil || arm.queued == nil || len(pending) == 0 || pending[0] != key || !sameObservedArm(arm.operation, r) {
					return ErrTraceTiming
				}
				pending = pending[1:]
				where := answerCoordinate{writer, r.EngineRun, r.Step}
				step := steps[where]
				if r.Source != "dequeue" || step == nil || step.Entry == nil || step.InputKind != inputlog.KindTimeout || !bytes.Equal(step.Input, r.Input) || r.Mono > step.Entry.Mono {
					return ErrTraceTiming
				}
				if t.pops[where] != nil {
					return ErrTraceTiming
				}
				t.pops[where] = r
			case "cancel":
				if r.Source != "core" && r.Source != "lifecycle" {
					return ErrTraceTiming
				}
				for _, kind := range r.Kinds {
					if _, exists := live[uint8(kind)]; exists {
						return ErrTraceTiming
					}
				}
			case "clear":
				if r.Source != "lifecycle" || r.Output != 0 {
					return ErrTraceTiming
				}
				live = map[uint8]observedArmKey{}
				pending = nil
			default:
				return ErrTraceTiming
			}
		}
		for _, r := range records {
			if r.Action != "replace" && r.Action != "cancelled" {
				continue
			}
			cause := t.operations[observedArmKey{writer, r.EngineRun, r.Step, r.Output}]
			if cause == nil {
				return ErrTraceTiming
			}
			input, err := inputlog.Decode(inputlog.KindTimeout, r.Input, nil)
			if err != nil {
				return err
			}
			timeout := input.(consensus.Timeout)
			if r.Action == "replace" {
				if cause.Action != "arm" {
					return ErrTraceTiming
				}
				next, err := inputlog.Decode(inputlog.KindTimeout, cause.Input, nil)
				if err != nil {
					return err
				}
				if next.(consensus.Timeout).Kind != timeout.Kind {
					return ErrTraceTiming
				}
			} else {
				if cause.Action != "cancel" {
					return ErrTraceTiming
				}
				found := false
				for _, kind := range cause.Kinds {
					if kind == uint64(timeout.Kind) {
						found = true
					}
				}
				if !found {
					return ErrTraceTiming
				}
			}
		}
	}
	for _, entry := range entries {
		if entry.record.InputKind == inputlog.KindTimeout && t.pops[answerCoordinate{entry.source.Writer, entry.source.Engine, entry.source.Step}] == nil {
			return ErrTraceTiming
		}
	}
	return nil
}
func sameObservedArm(arm, operation *journal.TimerRec) bool {
	return arm.EntryMono == operation.EntryMono && arm.Deadline == operation.Deadline && bytes.Equal(arm.Input, operation.Input)
}

// observedClock invokes the official scheduler callback only at its measured
// queue insertion time. An arm with no observed callback stays unfired within
// the finite retained horizon; it is not given a guessed future expiry.
type observedClock struct {
	*manualclock.Clock
	next *observedArm
	err  error
}
type retainedTimer struct{ stopped bool }

func (t *retainedTimer) Stop() bool {
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}
func (c *observedClock) AfterFunc(_ time.Duration, callback func()) runner.Timer {
	arm := c.next
	c.next = nil
	if arm == nil {
		c.err = ErrTraceTiming
		return &retainedTimer{}
	}
	if arm.queued == nil {
		return &retainedTimer{}
	}
	if arm.queued.Mono < c.Mono() {
		c.err = ErrTraceTiming
		return &retainedTimer{}
	}
	return c.At(arm.queued.Mono, callback)
}

func (t *observedTimers) validateOutputs(entry timedSourceEntry, outputs []consensus.Output) error {
	expected := map[observedArmKey]bool{}
	for i, output := range outputs {
		key := observedArmKey{entry.source.Writer, entry.source.Engine, entry.source.Step, uint64(i) + 1}
		operation := t.operations[key]
		switch o := output.(type) {
		case consensus.ArmTimer:
			expected[key] = true
			if operation == nil || operation.Action != "arm" || operation.EntryMono != entry.record.Entry.Mono || operation.Deadline != entry.record.Entry.Mono+o.Duration {
				return ErrTraceTiming
			}
			raw, err := inputlog.Encode(consensus.Timeout{Kind: o.Kind, View: o.View, Round: o.Round, Gen: o.Gen, Msg: o.Msg})
			if err != nil {
				return err
			}
			if !bytes.Equal(raw, operation.Input) {
				return ErrTraceTiming
			}
		case consensus.CancelTimers:
			expected[key] = true
			if operation == nil || operation.Action != "cancel" || len(operation.Kinds) != len(o.Kinds) {
				return ErrTraceTiming
			}
			for n, kind := range o.Kinds {
				if uint64(kind) != operation.Kinds[n] {
					return ErrTraceTiming
				}
			}
		default:
			if operation != nil {
				return ErrTraceTiming
			}
		}
	}
	for _, key := range t.byStep[answerCoordinate{entry.source.Writer, entry.source.Engine, entry.source.Step}] {
		if !expected[key] {
			return ErrTraceTiming
		}
	}
	return nil
}
