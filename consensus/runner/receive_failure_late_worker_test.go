package runner

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
)

// An existing observer holds a real worker after its intact owned signature
// has returned a local membership failure, before that result can be retained.
// Normal consensus inputs publish the next generation. This does not claim
// publication changes inside cryptographic recovery or inject network faults.
func TestReceiveFailureLateActualWorkerCannotRegisterInNewPublication(t *testing.T) {
	members, owned := newKeys(t, 4), newKeys(t, 5)
	n := newTNode(t, members, 1)
	n.noJournal = true
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	n.receiveFailureCache = &transport.ReceiveFailureOptions{Entries: 2}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var checks, hits atomic.Uint64
	n.receiveRecoveryChecked = func(_ codec.Code, phase consensus.RecoveryFailure) {
		if phase != consensus.RecoveryMembership {
			return
		}
		if checks.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	n.receiveFailureHit = func(_ uint64, class transport.ReceiveFailureClass) {
		if class != transport.ReceiveMembershipFailure {
			t.Error("membership reuse changed class")
		}
		hits.Add(1)
	}
	n.boot()
	started := false
	t.Cleanup(func() {
		unblock()
		if started {
			<-done
		}
		if err := n.r.Close(); err != nil {
			t.Error(err)
		}
		if err := n.log.Close(); err != nil {
			t.Error(err)
		}
	})
	b := block(t, 10, 1, members.addrs[0], codec.BlockHash(n.chain.head))
	raw := owned.vote(t, 4, codec.CodePrepare, view(10, 0), b)
	if recovered, err := consensus.Recover(codec.CodePrepare, raw, nil); err != nil || recovered.Source != owned.addrs[4] {
		t.Fatal("fixture lost its valid owned signature", err)
	}
	in := transportInbound(members, 0, codec.CodePrepare, raw, n.clock.now)
	old := n.r.snap.loadPublication()
	if !n.r.Receiver().Offer(in) {
		close(done)
		t.Fatal("normal local input refused")
	}
	var consumed atomic.Bool
	started = true
	go func() { defer close(done); consumed.Store(n.r.inbox.checkOne(true)) }()
	select {
	case <-entered:
	case <-t.Context().Done():
		t.Fatal("worker never reached its observed recovery boundary")
	}
	if checks.Load() != 1 || hits.Load() != 0 || n.r.receiveFailures.Len() != 0 {
		t.Fatal("in-flight result was prematurely retained")
	}
	n.deliver(0, codec.CodePreprepare, members.preprepare(t, 0, view(10, 0), b))
	n.deliver(0, codec.CodePrepare, members.vote(t, 0, codec.CodePrepare, view(10, 0), b))
	current := n.r.snap.loadPublication()
	if current == old || n.r.currentFailureContext(old) != nil || n.r.receiveFailures.Len() != 0 {
		t.Fatal("normal publication did not invalidate original ownership")
	}
	unblock()
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("late worker did not finish")
	}
	if !consumed.Load() || n.r.receiveFailures.Len() != 0 || checks.Load() != 1 || hits.Load() != 0 {
		t.Fatal("late completion registered a prior failure in the next generation")
	}
	for repeat := 0; repeat < 2; repeat++ {
		if !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) {
			t.Fatal("current publication input was not checked")
		}
		if checks.Load() != 2 || hits.Load() != uint64(repeat) || n.r.receiveFailures.Len() != 1 {
			t.Fatal("new generation skipped recovery or failed same-scope reuse", checks.Load(), hits.Load())
		}
	}
	context := n.r.receiveContext.Load()
	if context == nil || n.r.receiveCache.Known(context.scope, in.Code, in.Payload) || n.r.receiveCache.Recent(context.scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("failed result became accepted authority")
	}
	t.Log("actual_late_worker_after_recovery_new_publication_retained=false next_publication_actual_checks=1 same_scope_hits=1 cryptographic_failure_hit=false")
}
