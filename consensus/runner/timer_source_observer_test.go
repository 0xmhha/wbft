package runner

import (
	"bytes"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type timerSourceObservations struct {
	records []journal.TimerRec
	inspect func()
	alter   bool
}

func (o *timerSourceObservations) ObserveTimerSource(record journal.TimerRec) {
	if o.inspect != nil {
		o.inspect()
	}
	copy := record
	copy.Input, copy.Kinds = bytes.Clone(record.Input), slices.Clone(record.Kinds)
	o.records = append(o.records, copy)
	if o.alter {
		// These are observer-owned metadata copies, never submitted timer or
		// network input. Neither the live expiry nor legacy records may change.
		if len(record.Input) > 0 {
			record.Input[0] ^= 1
		}
		if len(record.Kinds) > 0 {
			record.Kinds[0] = ^uint64(0)
		}
	}
}

func TestTimerSourceObserverDetachedAfterUnlockAndOriginalOwner(t *testing.T) {
	clock := &manualClock{}
	var legacy []journal.TimerRec
	s := &scheduler{clock: clock, trace: func(r *journal.TimerRec) {
		copy := *r
		copy.Input, copy.Kinds = bytes.Clone(r.Input), slices.Clone(r.Kinds)
		legacy = append(legacy, copy)
	}}
	o := &timerSourceObservations{alter: true, inspect: func() { _ = s.pending() }}
	s.observe = o.ObserveTimerSource
	view := types.View{Sequence: types.HeightFromUint64(10)}
	s.setOwner(4, 1, 1, "core")
	s.arm(consensus.ArmTimer{Kind: consensus.RoundTimer, View: view, Gen: 7, Duration: 2 * time.Second}, 0)
	s.setOwner(4, 2, 2, "core")
	s.arm(consensus.ArmTimer{Kind: consensus.RetryTimer, View: view, Gen: 8, Duration: 4 * time.Second}, 0)
	clock.advance(2 * time.Second)
	s.cancel(consensus.AllTimers)
	s.setOwner(4, 3, 0, "dequeue")
	expiry, ok := s.pop()
	if !ok || expiry.Kind != consensus.RoundTimer || expiry.Gen != 7 || expiry.View.Cmp(view) != 0 {
		t.Fatal("observer metadata changed the original normal expiry", expiry, ok)
	}
	s.clear()
	if !reflect.DeepEqual(legacy, o.records) {
		t.Fatal("detached observer changed a legacy record or lost a mutation")
	}
	var queued, popped *journal.TimerRec
	for i := range o.records {
		r := &o.records[i]
		if r.Sequence != uint64(i+1) {
			t.Fatal("original mutex sequence lost", r)
		}
		if len(r.Input) > 0 {
			if _, err := inputlog.Decode(inputlog.KindTimeout, r.Input, nil); err != nil {
				t.Fatal("observer altered retained legacy bytes", err)
			}
		}
		if r.Action == "queued" {
			queued = r
		}
		if r.Action == "pop" {
			popped = r
		}
	}
	if queued == nil || popped == nil || queued.Step != 1 || queued.Output != 1 || queued.ArmStep != 1 || popped.Step != 3 || popped.ArmStep != 1 {
		t.Fatal("expiry callback borrowed the current owner", queued, popped)
	}
}

func TestTimerSourceObserverRunnerWithoutFunctionalJournal(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	o := &timerSourceObservations{alter: true}
	o.inspect = func() { _ = n.r.timers.pending() }
	n.timerSources = o
	n.boot()
	if n.r.d.Journal != nil || len(o.records) == 0 {
		t.Fatal("diagnostic scheduler source required a functional journal")
	}
	n.advance(3 * time.Second)
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	queued := 0
	for _, r := range o.records {
		if r.EngineRun == 0 || r.Sequence == 0 {
			t.Fatal("source owner missing", r)
		}
		if r.Action == "queued" {
			queued++
		}
	}
	if queued == 0 {
		t.Fatal("actual normal timeout callback source not observed")
	}
}

func TestTimerSourceObserverOrdinaryConcurrentClockCallbacks(t *testing.T) {
	clock := SystemClock()
	s := &scheduler{clock: clock}
	t.Cleanup(s.clear)
	var mu sync.Mutex
	records := map[uint64]journal.TimerRec{}
	queued := make(chan journal.TimerRec, 2)
	s.observe = func(r journal.TimerRec) {
		_ = s.pending()
		mu.Lock()
		if _, duplicate := records[r.Sequence]; duplicate {
			mu.Unlock()
			t.Error("original scheduler sequence reused")
			return
		}
		records[r.Sequence] = r
		mu.Unlock()
		if r.Action == "queued" {
			queued <- r
		}
	}
	view := types.View{Sequence: types.HeightFromUint64(10)}
	s.setOwner(5, 1, 1, "core")
	s.arm(consensus.ArmTimer{Kind: consensus.RoundTimer, View: view, Gen: 1, Duration: 10 * time.Millisecond}, clock.Mono())
	s.setOwner(5, 2, 1, "core")
	s.arm(consensus.ArmTimer{Kind: consensus.RetryTimer, View: view, Gen: 2, Duration: 10 * time.Millisecond}, clock.Mono())
	for range 2 {
		select {
		case r := <-queued:
			if r.EngineRun != 5 || r.Step != r.ArmStep || r.Output != r.ArmOutput {
				t.Fatal("clock callback inherited a later owner", r)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ordinary timer source callback did not finish")
		}
	}
	s.setOwner(5, 3, 0, "dequeue")
	kinds := map[consensus.TimerKind]bool{}
	for range 2 {
		expiry, ok := s.pop()
		if !ok || kinds[expiry.Kind] {
			t.Fatal("ordinary queued timer lost or duplicated", expiry, ok)
		}
		kinds[expiry.Kind] = true
	}
	s.clear()
	mu.Lock()
	defer mu.Unlock()
	for next := uint64(1); next <= uint64(len(records)); next++ {
		if records[next].Sequence != next {
			t.Fatal("mutex sequence gap", next)
		}
	}
}

func TestTimerSourceObserverExhaustionDoesNotReuseOrChangeExpiry(t *testing.T) {
	clock := &manualClock{}
	o := &timerSourceObservations{}
	s := &scheduler{clock: clock, observe: o.ObserveTimerSource, sequence: ^uint64(0) - 1}
	s.setOwner(6, 1, 1, "core")
	view := types.View{Sequence: types.HeightFromUint64(10)}
	s.arm(consensus.ArmTimer{Kind: consensus.RoundTimer, View: view, Gen: 7, Duration: time.Second}, 0)
	s.arm(consensus.ArmTimer{Kind: consensus.RetryTimer, View: view, Gen: 8, Duration: time.Second}, 0)
	clock.advance(time.Second)
	for range 2 {
		if _, ok := s.pop(); !ok {
			t.Fatal("observation exhaustion changed normal expiry")
		}
	}
	if len(o.records) < 6 || o.records[0].Sequence != ^uint64(0) {
		t.Fatal("last available original sequence lost")
	}
	for _, record := range o.records[1:] {
		if record.Sequence != 0 {
			t.Fatal("exhausted timer observation namespace reused", record.Sequence)
		}
	}
}
