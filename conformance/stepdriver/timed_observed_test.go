package stepdriver

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestObservedClockKeepsCallbackQueuedDuringProcessingBeforeCancel(t *testing.T) {
	base := manualclock.New(time.Unix(0, 0))
	clock := &observedClock{Clock: base}
	queue := runner.NewTimerQueue(clock)
	clock.next = &observedArm{operation: &journal.TimerRec{Deadline: 10}, queued: &journal.TimerRec{Mono: 12}}
	queue.Arm(consensus.ArmTimer{Kind: consensus.RetryTimer, Gen: 3, Duration: 10}, 0)
	base.AdvanceTo(11)
	if queue.Pending() {
		t.Fatal("deadline used instead of observed callback time")
	}
	base.AdvanceTo(13)
	queue.Cancel(consensus.AllTimers)
	got, ok := queue.Pop()
	if !ok || got.Gen != 3 {
		t.Fatal("queued-before-cancel expiry lost", got, ok)
	}
	clock.next = &observedArm{operation: &journal.TimerRec{Deadline: 20}}
	queue.Arm(consensus.ArmTimer{Kind: consensus.RoundTimer, Gen: 4, Duration: 7}, 13)
	base.AdvanceTo(30)
	if queue.Pending() {
		t.Fatal("unobserved callback manufactured")
	}
}
func TestObservedTimersRejectMissingOrAlteredOperationEvidence(t *testing.T) {
	input, err := inputlog.Encode(consensus.Timeout{Kind: consensus.RoundTimer, Gen: 2})
	if err != nil {
		t.Fatal(err)
	}
	entries := []timedSourceEntry{
		{record: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart, Entry: &journal.StepMoment{Mono: 0}, Mono: 1}, source: TimedSource{Writer: "synthetic", Engine: 1, Step: 1}, config: journal.CoreOptions{TimerTrace: 1}},
		{record: &journal.StepRec{EngineRun: 1, Step: 2, InputKind: inputlog.KindTimeout, Input: input, Entry: &journal.StepMoment{Mono: 12}, Mono: 13}, source: TimedSource{Writer: "synthetic", Engine: 1, Step: 2}, config: journal.CoreOptions{TimerTrace: 1}},
	}
	makeEvidence := func() *observedTimers {
		proof := newObservedTimers()
		proof.records["synthetic"] = []*journal.TimerRec{
			{Sequence: 1, EngineRun: 1, Step: 1, Output: 1, ArmEngineRun: 1, ArmStep: 1, ArmOutput: 1, Source: "core", Action: "arm", Mono: 1, Deadline: 10, Input: input},
			{Sequence: 2, EngineRun: 1, Step: 1, Output: 1, ArmEngineRun: 1, ArmStep: 1, ArmOutput: 1, Source: "core", Action: "queued", Mono: 11, Deadline: 10, Input: input},
			{Sequence: 3, EngineRun: 1, Step: 2, ArmEngineRun: 1, ArmStep: 1, ArmOutput: 1, Source: "dequeue", Action: "pop", Mono: 12, Deadline: 10, Input: input},
		}
		return proof
	}
	for _, variant := range []string{"sequence", "premature", "input", "pop", "capability", "output", "cause"} {
		proof := makeEvidence()
		source := append([]timedSourceEntry(nil), entries...)
		switch variant {
		case "cause":
			proof.records["synthetic"][1].Step = 9
		case "sequence":
			proof.records["synthetic"][1].Sequence = 4
		case "premature":
			proof.records["synthetic"][1].Mono = 9
		case "input":
			proof.records["synthetic"][1].Input = bytes.Clone(input)
			proof.records["synthetic"][1].Input[len(input)-1] ^= 1
		case "pop":
			proof.records["synthetic"] = proof.records["synthetic"][:2]
		case "capability":
			source[0].config.TimerTrace = 0
		case "output":
			proof.records["synthetic"][0].Output = 0
		}
		if err := proof.validate(source); err == nil {
			t.Fatal("invalid proof accepted", variant)
		}
	}
	proof := makeEvidence()
	if err := proof.validate(entries); err != nil {
		t.Fatal(err)
	}
	outputs := []consensus.Output{consensus.ArmTimer{Kind: consensus.RoundTimer, Gen: 2, Duration: 10}}
	if err := proof.validateOutputs(entries[0], outputs); err != nil {
		t.Fatal(err)
	}
	outputs[0] = consensus.ArmTimer{Kind: consensus.RoundTimer, Gen: 2, Duration: 9}
	if err := proof.validateOutputs(entries[0], outputs); err == nil {
		t.Fatal("changed deadline accepted")
	}
}
