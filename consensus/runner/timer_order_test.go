package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
)

// The expiry of a future-proposal timer that is already queued when a
// second deferred PRE-PREPARE replaces the timer is still processed, as in
// the reference: the first proposal is re-processed when its expiry is
// handled, and the node sends PREPARE for it.
func TestFutureExpiryQueuedBeforeReplacement(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	// Take the peer queue before the timer queue when both have input.
	n.r.d.Rand = func(n int) int { return n - 1 }

	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	b := block(t, 10, 2, k.addrs[0], codec.BlockHash(n.chain.head))
	n.chain.future[codec.BlockHash(a.Header)] = 100 * time.Millisecond
	n.chain.future[codec.BlockHash(b.Header)] = 300 * time.Millisecond

	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))
	if len(n.net.own(codec.CodePrepare)) != 0 {
		t.Fatal("PREPARE for a proposal from the future")
	}
	// A's timer fires; before its expiry is handled, B arrives and is
	// deferred, replacing the timer.
	n.clock.advance(100 * time.Millisecond)
	if !n.r.timers.pending() {
		t.Fatal("expiry of A not queued")
	}
	n.r.Receiver().Offer(transportInbound(k, 0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b), n.clock.now))
	n.r.Pump()
	prepares := n.net.own(codec.CodePrepare)
	if len(prepares) != 1 {
		t.Fatalf("PREPAREs sent: %d", len(prepares))
	}
	m, err := codec.DecodeMessage(codec.CodePrepare, prepares[0])
	if err != nil {
		t.Fatal(err)
	}
	if m.Digest != codec.BlockHash(a.Header) {
		t.Fatalf("PREPARE for %x, want the first proposal %x", m.Digest[:4], codec.BlockHash(a.Header).Bytes()[:4])
	}
	// B's later expiry finds the node in Preprepared: nothing more is sent.
	n.advance(300 * time.Millisecond)
	if got := len(n.net.own(codec.CodePrepare)); got != 1 {
		t.Fatalf("PREPAREs after B's expiry: %d", got)
	}
	if v := n.r.Vars(); v.State != consensus.Preprepared {
		t.Fatalf("state %s", v.State)
	}
}
