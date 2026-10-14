package runner

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"testing"
	"time"
)

func TestTimerTracePreservesQueuedExpiryDuringProcessingBeforeCancel(t *testing.T) {
	clock := &manualClock{}
	var trace []*journal.TimerRec
	scheduler := &scheduler{clock: clock, trace: func(r *journal.TimerRec) { trace = append(trace, r) }}
	view := types.View{Sequence: types.HeightFromUint64(10)}
	scheduler.setOwner(2, 1, 1, "core")
	scheduler.arm(consensus.ArmTimer{Kind: consensus.RoundTimer, View: view, Gen: 7, Duration: 4 * time.Second}, 0)
	scheduler.setOwner(2, 1, 2, "core")
	scheduler.arm(consensus.ArmTimer{Kind: consensus.RetryTimer, View: view, Gen: 3, Duration: 4*time.Second + 100*time.Nanosecond}, 0)
	clock.advance(4 * time.Second)
	scheduler.setOwner(2, 2, 0, "dequeue")
	if got, ok := scheduler.pop(); !ok || got.Kind != consensus.RoundTimer {
		t.Fatal(got, ok)
	}
	// The other callback queues during this handler, before CancelTimers runs.
	scheduler.setOwner(2, 2, 1, "core")
	clock.advance(4*time.Second + 200*time.Nanosecond)
	scheduler.cancel(consensus.AllTimers)
	scheduler.setOwner(2, 3, 0, "dequeue")
	if got, ok := scheduler.pop(); !ok || got.Kind != consensus.RetryTimer || got.Gen != 3 {
		t.Fatal("queued expiry lost", got, ok)
	}
	var queued, cancel, popped *journal.TimerRec
	for i, record := range trace {
		if record.Sequence != uint64(i+1) {
			t.Fatal("operation sequence lost", record)
		}
		if record.Action == "cancel" {
			cancel = record
			if len(record.Kinds) != 3 {
				t.Fatal("empty cancellation omitted", record)
			}
		}
		if len(record.Input) == 0 {
			continue
		}
		input, err := inputlog.Decode(inputlog.KindTimeout, record.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		timeout := input.(consensus.Timeout)
		if timeout.Kind == consensus.RetryTimer && record.Action == "queued" {
			queued = record
		}
		if timeout.Kind == consensus.RetryTimer && record.Action == "pop" {
			popped = record
		}
	}
	if queued == nil || cancel == nil || popped == nil || queued.Sequence >= cancel.Sequence || cancel.Sequence >= popped.Sequence || queued.Mono >= cancel.Mono {
		t.Fatal("queue/cancel causal order lost", queued, cancel, popped)
	}
	if queued.EngineRun != 2 || queued.Step != 1 || queued.Output != 2 || queued.ArmStep != 1 || popped.Step != 3 {
		t.Fatal("callback inherited current step", queued, popped)
	}
}
