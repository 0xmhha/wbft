package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestManualProcessingKeepsExpiryQueuedDuringCoreService(t *testing.T) {
	n := manualServiceNode(t, 1, func(w ProcessingWork) time.Duration {
		if w.Kind == "peer_connected" {
			return time.Second
		}
		return 0
	})
	n.r.timers.arm(consensus.ArmTimer{Kind: consensus.RoundTimer, Duration: 50 * time.Millisecond, Gen: 99}, n.clock.Mono())
	n.r.PeerConnected(n.k.addrs[0])
	n.r.Pump()
	before := n.r.step
	n.clock.advance(50 * time.Millisecond)
	if !n.r.timers.pending() || !n.r.ProcessingPending() || n.r.step != before {
		t.Fatal("expiry did not queue during service")
	}
	n.r.timers.cancel([]consensus.TimerKind{consensus.RoundTimer})
	if !n.r.timers.pending() {
		t.Fatal("later cancellation removed an already queued expiry")
	}
	n.clock.advance(time.Second)
	n.r.Pump()
	if n.r.timers.pending() || len(n.events.kinds(event.TimerFire)) == 0 {
		t.Fatal("queued expiry was not dispatched after service")
	}
}

func manualServiceNode(t *testing.T, workers int, delay func(ProcessingWork) time.Duration) *tnode {
	t.Helper()
	n := newTNode(t, newKeys(t, 4), 1)
	n.boot()
	n.r.Pump()
	n.r.cfg.Workers = workers
	n.r.d.ManualProcessing = &ManualProcessing{Delay: delay, Schedule: func(d time.Duration, f func()) { n.clock.AfterFunc(d, f) }}
	return n
}

func TestManualProcessingReservesOneCoreInputAndIndependentCheckWorkers(t *testing.T) {
	n := manualServiceNode(t, 2, func(w ProcessingWork) time.Duration {
		if w.Phase == ProcessingCore {
			return 100 * time.Millisecond
		}
		return 20 * time.Millisecond
	})
	n.r.PeerConnected(n.k.addrs[0])
	before := n.r.step
	if !n.r.Pump() || !n.r.ProcessingPending() || n.r.step != before {
		t.Fatal("reserved input was executed before service completion")
	}
	n.r.PeerConnected(n.k.addrs[2])
	for i := range 3 {
		if !n.r.Receiver().Offer(transport.Inbound{Peer: n.k.addrs[0], Code: uint64(codec.CodePrepare), Payload: []byte{byte(128 + i)}}) {
			t.Fatal("queue offer rejected")
		}
	}
	if !n.r.Pump() || n.r.manualChecks != 2 || n.r.InboundBytes() != 1 || n.r.Pump() {
		t.Fatal("worker capacity or consensus occupancy not preserved")
	}
	n.clock.advance(20 * time.Millisecond)
	if n.r.manualChecks != 0 || len(n.events.kinds(event.MsgOutcome)) != 2 || n.r.step != before {
		t.Fatal("checks did not finish independently of core service")
	}
	n.r.Pump()
	if n.r.manualChecks != 1 || n.r.InboundBytes() != 0 {
		t.Fatal("released worker did not take queued work")
	}
	if err := n.r.Stop(); !errors.Is(err, ErrProcessingPending) || !n.r.Running() {
		t.Fatal("stop overtook reserved core input", err)
	}
	if err := n.r.Close(); !errors.Is(err, ErrProcessingPending) || n.r.closed {
		t.Fatal("close discarded reserved core input", err)
	}
	n.clock.advance(100 * time.Millisecond)
	if n.r.ProcessingPending() || n.r.step != before+1 || n.r.manualChecks != 0 || len(n.r.appQ) != 1 {
		t.Fatal("reserved work did not complete exactly once")
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestManualProcessingDiscardsOldEngineCheckCompletion(t *testing.T) {
	n := manualServiceNode(t, 1, func(w ProcessingWork) time.Duration {
		if w.Phase == ProcessingCheck {
			return time.Second
		}
		return 0
	})
	offer := func(payload byte) {
		n.r.Receiver().Offer(transport.Inbound{Peer: n.k.addrs[0], Code: uint64(codec.CodePrepare), Payload: []byte{payload}})
		n.r.Pump()
	}
	offer(128)
	if n.r.manualChecks != 1 {
		t.Fatal("check did not remain pending")
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	if n.r.manualChecks != 0 {
		t.Fatal("old engine capacity leaked across restart")
	}
	offer(129)
	before := len(n.events.kinds(event.MsgOutcome))
	n.clock.advance(time.Second)
	if n.r.manualChecks != 0 || len(n.events.kinds(event.MsgOutcome)) != before+1 {
		t.Fatal("old completion changed the new engine or its worker count")
	}
}

func TestManualProcessingRejectsInvalidConfigurationAndNegativeCost(t *testing.T) {
	n := manualServiceNode(t, 1, func(ProcessingWork) time.Duration { return -1 })
	if _, err := New(Config{Core: n.opts}, n.r.d); err == nil {
		t.Fatal("production runner accepted manual service callbacks")
	}
	if _, err := New(Config{Core: n.opts, Manual: true}, n.r.d); err == nil {
		t.Fatal("implicit host worker count accepted")
	}
	n.r.PeerConnected(n.k.addrs[0])
	before := n.r.step
	n.r.Pump()
	if n.r.Halted() == nil || n.r.ProcessingPending() || n.r.step != before {
		t.Fatal("negative cost executed input or reserved unfinishable work")
	}
}
