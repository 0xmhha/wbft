package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestReplayTimerReportsItsScheduledDeadline(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.clock.tick = time.Microsecond
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	n.crash()
	n.clock.now += time.Second
	n.boot()
	if info := n.r.LastReplay(); !info.Replayed || info.Records == 0 {
		t.Fatalf("WAL replay not exercised: %+v", info)
	}
	assertRestoredDeadline(t, n, consensus.RoundTimer)
}

func TestRestoredTimersKeepDeadlineAndTimeoutContext(t *testing.T) {
	for _, kind := range consensus.AllTimers {
		t.Run(kind.String(), func(t *testing.T) {
			n := newTNode(t, newKeys(t, 4), 1)
			n.clock.tick = time.Microsecond
			n.boot()
			n.r.timers.clear()
			n.events.recs, n.events.stamps = nil, nil
			arm := consensus.ArmTimer{Kind: kind, View: view(10, 2), Round: types.RoundFromUint64(5), Gen: 17, Duration: 2 * time.Second}
			var restored [3]*consensus.ArmTimer
			restored[kind] = &arm
			n.r.afterReplay(restored, n.r.Snapshot())
			deadline := assertRestoredDeadline(t, n, kind)
			if kind == consensus.RetryTimer {
				if got := n.events.recs[0].Fields["target_round"]; got != arm.Round.String() {
					t.Fatalf("retry target round %v, want %s", got, arm.Round)
				}
			} else if _, exists := n.events.recs[0].Fields["target_round"]; exists {
				t.Fatal("non-retry timer has a target round")
			}
			// Exercise the scheduled callback, without the core consuming it.
			n.clock.advance(deadline - time.Nanosecond)
			if n.r.timers.pending() {
				t.Fatal("restored timer fired before its recorded deadline")
			}
			n.clock.advance(deadline)
			got, ok := n.r.timers.pop()
			if !ok || got.Kind != kind || got.View != arm.View || got.Round != arm.Round || got.Gen != arm.Gen {
				t.Fatalf("restored timeout context lost: %+v, available=%v", got, ok)
			}
		})
	}
}

func assertRestoredDeadline(t *testing.T, n *tnode, kind consensus.TimerKind) time.Duration {
	t.Helper()
	for i, record := range n.events.recs {
		if record.Kind != event.TimerArm || record.Fields["rearmed"] != true || record.Fields["timer"] != kind.String() {
			continue
		}
		deadline, ok := record.Fields["deadline_mono_ns"].(int64)
		if !ok {
			t.Fatal("restored timer has no logical deadline")
		}
		entry := n.r.timers.live[kind]
		if entry == nil {
			t.Fatal("restored timer is not live")
		}
		actual := entry.t.(mTimer).e.at
		if time.Duration(deadline) != actual {
			t.Fatalf("reported deadline %v, scheduled callback at %v", time.Duration(deadline), actual)
		}
		stamp := n.events.stamps[i]
		if stamp.Step != nil || stamp.Mono <= actual-entry.arm.Duration {
			t.Fatal("restored event must retain its later writing moment", stamp)
		}
		if record.Fields["gen"] != entry.arm.Gen || record.Fields["engine_run"] != n.r.engineRun || *record.View != *event.ViewOf(entry.arm.View) {
			t.Fatal("restored timer identity differs from its event", record)
		}
		return actual
	}
	t.Fatalf("no restored %s timer event", kind)
	return 0
}
