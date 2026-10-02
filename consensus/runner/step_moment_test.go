package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
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
