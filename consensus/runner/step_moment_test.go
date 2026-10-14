package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
)

// The events of one step carry one moment, the start of the step, and the
// round timer armed on entering a view (WBFT-TIMER-010) or on accepting a
// PRE-PREPARE (WBFT-TIMER-012) runs from that moment, although the clock
// moves while the step runs.
func TestStepEventsShareTheStepMoment(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.clock.tick = time.Microsecond
	n.boot()
	a := block(t, 10, 0, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))

	l := n.events
	l.mu.Lock()
	defer l.mu.Unlock()
	moment := map[uint64]time.Duration{}
	arms := map[uint64]int{} // step -> index of its round TIMER_ARM
	for i, at := range l.stamps {
		if at.Step == nil {
			continue
		}
		if m, ok := moment[*at.Step]; ok && m != at.Mono {
			t.Fatalf("step %d: %s at %v, an earlier event at %v", *at.Step, l.recs[i].Kind, at.Mono, m)
		}
		moment[*at.Step] = at.Mono
		if r := l.recs[i]; r.Kind == event.TimerArm && r.Fields["timer"] == consensus.RoundTimer.String() {
			arms[*at.Step] = i
		}
	}
	var last time.Duration
	for _, kind := range []event.Kind{event.RoundEnter, event.PreprepareAccept} {
		found := false
		for i, r := range l.recs {
			if r.Kind != kind {
				continue
			}
			found = true
			j, ok := arms[*l.stamps[i].Step]
			if !ok {
				t.Fatalf("%s without a round TIMER_ARM in its step", kind)
			}
			f := l.recs[j].Fields
			want := l.stamps[i].Mono + time.Duration(f["duration_ms"].(int64))*time.Millisecond
			if got := time.Duration(f["deadline_mono_ns"].(int64)); got != want {
				t.Fatalf("%s: deadline %v, want the step moment plus the duration %v", kind, got, want)
			}
			last = want
		}
		if !found {
			t.Fatalf("no %s", kind)
		}
	}
	// The live round timer fires at the deadline it reported.
	for _, e := range n.clock.q {
		if !e.dead && e.at == last {
			return
		}
	}
	t.Fatalf("no live timer at the reported deadline %v", last)
}

func TestJournalEntryMatchesEventMomentAndPrecedesCompletion(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.clock.tick = time.Microsecond
	n.boot()
	a := block(t, 10, 0, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))
	if e := n.r.d.Journal.(*journal.FileWriter).Sync(); e != nil {
		t.Fatal(e)
	}
	records, e := journal.ReadAll(n.jfs, "/j")
	if e != nil {
		t.Fatal(e)
	}
	n.events.mu.Lock()
	defer n.events.mu.Unlock()
	moments := map[uint64]event.Stamp{}
	for _, s := range n.events.stamps {
		if s.Step != nil {
			moments[*s.Step] = s
		}
	}
	checked := 0
	for _, r := range records {
		if s, ok := r.Body.(*journal.StepRec); ok {
			m, exists := moments[s.Step]
			if !exists || s.Entry == nil || s.Entry.Mono != m.Mono || s.Entry.WallNs != m.Wall.UnixNano() || s.Entry.Mono >= s.Mono {
				t.Fatal("entry/completion evidence inconsistent", s, m)
			}
			checked++
		}
	}
	if checked < 2 {
		t.Fatal("start and peer input not covered")
	}
}

func TestJournalStopHasItsOwnEntryMoment(t *testing.T) {
	n := newTNode(t, newKeys(t, 4), 1)
	n.clock.tick = time.Microsecond
	n.boot()
	n.clock.now += time.Second
	stopBefore := n.clock.now
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		step, ok := record.Body.(*journal.StepRec)
		if !ok || step.InputKind != "stop" {
			continue
		}
		found = true
		if step.Entry == nil || step.Entry.Mono < stopBefore || step.Entry.Mono > step.Mono {
			t.Fatal("stop reused prior step entry", step)
		}
	}
	if !found {
		t.Fatal("stop step missing")
	}
}
