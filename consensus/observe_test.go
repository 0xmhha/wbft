package consensus

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
)

func eventsOf(outs []Output, kind event.Kind) []event.Record {
	var r []event.Record
	for _, e := range outputsOf[Event](outs) {
		if e.Record.Kind == kind {
			r = append(r, e.Record)
		}
	}
	return r
}

// The proposer of (10, 0) is validator 0. Without the restart-safety rule a
// second request before the first PRE-PREPARE reached the proposer's own
// state sends a second PRE-PREPARE (the reference); with it nothing is sent.
func TestOneRound0Proposal(t *testing.T) {
	for _, guard := range []bool{false, true} {
		h := newHarness(t, 4, 0)
		if guard {
			h.s = NewState(Options{Config: h.cfg, Self: h.addrs[0], Improvements: RestartSafety})
		}
		h.start()
		h.step(Request{Block: h.proposal(1)})
		if len(h.broadcasts()) != 1 {
			t.Fatalf("first request: %v", h.out)
		}
		h.step(Request{Block: h.proposal(2)})
		got := len(h.broadcasts())
		if guard && got != 0 || !guard && got != 1 {
			t.Fatalf("guard %v: second request sent %d PRE-PREPAREs", guard, got)
		}
		if guard {
			// A PRE-PREPARE that was not sent (privval refusal) does not
			// count.
			h.step(BroadcastFailed{Code: codec.CodePreprepare, View: view(10, 0)})
			h.step(Request{Block: h.proposal(1)})
			if len(h.broadcasts()) != 1 {
				t.Fatalf("after BroadcastFailed: %v", h.out)
			}
		}
	}
}

func TestRoundEnterValsetDigest(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	enters := eventsOf(h.out, event.RoundEnter)
	if len(enters) != 1 || enters[0].Fields["valset_digest"] != hexHash(ValsetDigest(h.vs)) {
		t.Fatalf("ROUND_ENTER %v", enters)
	}
	if ValsetDigest(nil) != [32]byte{} || ValsetDigest(h.vs) == [32]byte{} {
		t.Fatal("digest of nil and non-empty sets")
	}
}

// Two different PREPAREs of one source for one view are EVIDENCE of kind
// equivocation; the handling of the second is unchanged.
func TestEvidenceEquivocation(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.deliver(2, h.prepare(2, view(10, 0), b))
	if len(eventsOf(h.out, event.Evidence)) != 0 {
		t.Fatal("evidence for a first message")
	}
	h.deliver(2, h.prepare(2, view(10, 0), h.proposal(9)))
	ev := eventsOf(h.out, event.Evidence)
	if len(ev) != 1 || ev[0].Fields["kind"] != "equivocation" || ev[0].Fields["code"] != uint64(codec.CodePrepare) {
		t.Fatalf("evidence %v", ev)
	}
	h.expect(Process, rowPrepareInvalid, false)
	// The same message again is no evidence.
	h.deliver(2, h.prepare(2, view(10, 0), b))
	if len(eventsOf(h.out, event.Evidence)) != 0 {
		t.Fatal("evidence for a repeated message")
	}
}

func TestBacklogAndExtraSealEvents(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	// A COMMIT in AcceptRequest is FUTURE: pushed.
	h.deliver(2, h.commit(2, view(10, 0), b))
	if ev := eventsOf(h.out, event.Backlog); len(ev) != 1 || ev[0].Fields["op"] != "push" {
		t.Fatalf("push %v", ev)
	}
	h.deliver(2, h.commit(2, view(10, 0), b))
	if ev := eventsOf(h.out, event.Backlog); len(ev) != 1 || ev[0].Fields["op"] != "drop" || ev[0].Fields["reason"] != "duplicate" {
		t.Fatalf("duplicate %v", ev)
	}
	// Reaching Prepared releases it.
	h.reachPrepared(b)
	if ev := eventsOf(h.out, event.Backlog); len(ev) != 1 || ev[0].Fields["op"] != "replay" {
		t.Fatalf("replay %v", ev)
	}
	// A PREPARE in Prepared is an extra seal of the current proposal.
	h.deliver(3, h.prepare(3, view(10, 0), b))
	if ev := eventsOf(h.out, event.ExtraSeal); len(ev) != 1 || ev[0].Fields["op"] != "store" || ev[0].Fields["seal_type"] != "PREPARE" || ev[0].Fields["target"] != hexHash(blockHash(b)) {
		t.Fatalf("extra seal %v", ev)
	}
	h.deliver(3, h.prepare(3, view(10, 0), b))
	if ev := eventsOf(h.out, event.ExtraSeal); len(ev) != 1 || ev[0].Fields["op"] != "ignore" {
		t.Fatalf("not newer %v", ev)
	}
}

// An expiry of a replaced future-proposal timer that was queued before the
// replacement re-processes its PRE-PREPARE (the reference processes the
// queued event); an expiry without its message and with an old generation
// does nothing.
func TestQueuedFutureExpiryAfterReplacement(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	a, b := h.proposal(1), h.proposal(2)
	h.env.future[blockHash(a)] = time.Second
	h.env.future[blockHash(b)] = time.Second
	h.deliver(0, h.preprepare(0, view(10, 0), a, nil, nil))
	armA := outputsOf[ArmTimer](h.out)[0]
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	armB := outputsOf[ArmTimer](h.out)[0]
	if armA.Msg == nil || armB.Gen == armA.Gen {
		t.Fatalf("timers %+v %+v", armA, armB)
	}
	h.step(Timeout{Kind: FutureTimer, Gen: armA.Gen})
	if len(h.out) != 0 {
		t.Fatalf("stale expiry without message: %v", h.out)
	}
	delete(h.env.future, blockHash(a))
	h.step(Timeout{Kind: FutureTimer, Gen: armA.Gen, Msg: armA.Msg})
	sch := outputsOf[Schedule](h.out)
	if len(sch) != 1 || blockHash(sch[0].In.(Replay).Msg.Msg.Proposal) != blockHash(a) {
		t.Fatalf("queued expiry of A: %v", h.out)
	}
	h.step(sch[0].In)
	h.expect(Process, rowPreprepareAccept, true)
	// B's timer is still armed; its expiry finds the node in Preprepared.
	h.step(Timeout{Kind: FutureTimer, Gen: armB.Gen, Msg: armB.Msg})
	h.step(outputsOf[Schedule](h.out)[0].In)
	h.expect(Invalid, rowInvalid, false)
}
