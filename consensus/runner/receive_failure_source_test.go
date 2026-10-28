package runner

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Only intact, owned signatures reach the local receiver. The explicit cache
// query below inspects the original actual worker registration; it is not a
// diagnostic transcript, a socket test, or cryptographic-failure evidence.
func TestReceiveFailureActualWorkerRetainsOriginalPublicationAndRequest(t *testing.T) {
	members, owned := newKeys(t, 4), newKeys(t, 5)
	n := newTNode(t, members, 1)
	n.noJournal = true
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	n.receiveFailureCache = &transport.ReceiveFailureOptions{Entries: 2}
	checks, hits := 0, 0
	n.receiveRecoveryChecked = func(_ codec.Code, failure consensus.RecoveryFailure) {
		if failure != consensus.RecoveryMembership {
			t.Error("ordinary authority mismatch changed its failed verification phase")
		}
		checks++
	}
	n.receiveFailureHit = func(_ uint64, class transport.ReceiveFailureClass) {
		if class != transport.ReceiveMembershipFailure {
			t.Error("prior membership result changed class")
		}
		hits++
	}
	n.boot()
	t.Cleanup(func() {
		if err := n.r.Close(); err != nil {
			t.Error(err)
		}
		if err := n.log.Close(); err != nil {
			t.Error(err)
		}
	})
	b := block(t, 10, 1, members.addrs[0], codec.BlockHash(n.chain.head))
	raw := owned.vote(t, 4, codec.CodePrepare, view(10, 0), b)
	if verified, err := consensus.Recover(codec.CodePrepare, raw, nil); err != nil || verified.Source != owned.addrs[4] {
		t.Fatal("fixture did not retain its valid owned signature", err)
	}
	in := transportInbound(members, 0, codec.CodePrepare, raw, n.clock.now)
	var previousRequest uint64
	for engine := uint64(1); engine <= 2; engine++ {
		publication := n.r.snap.loadPublication()
		digest, err := journal.InboxSnapshotDigest(publication.snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !n.r.Receiver().Offer(in) {
			t.Fatal("local receiver refused ordinary signed input")
		}
		request := n.r.inbox.sourceSequence
		if request == 0 || request <= previousRequest || !n.r.inbox.checkOne(true) {
			t.Fatal("original append identity was reused or not consumed")
		}
		previousRequest = request
		failureContext := n.r.currentFailureContext(publication)
		if failureContext == nil {
			t.Fatal("actual checking publication lost its cache context")
		}
		query := failureWorkerSource(publication, request)
		retained, ok := n.r.receiveFailures.Lookup(failureContext, in, query)
		want := transport.ReceiveFailureSource{EngineRun: engine, SnapshotStep: publication.owner.step, WorkerRequest: request, SnapshotPhase: failurePublicationPhase(publication.owner.phase), SnapshotHash: digest}
		if !ok || retained.Source != want || retained.Class != transport.ReceiveMembershipFailure || retained.Reference.Run != "" {
			t.Fatal("original actual worker coordinates changed or an absent namespace was fabricated", retained, want)
		}
		if !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) || checks != int(engine) || hits != int(engine) {
			t.Fatal("ordinary reuse executed a new verifier or failed to retain its original request", checks, hits)
		}
		if engine == 1 {
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
				t.Fatal(err)
			}
			n.r.Pump()
		}
	}
	t.Log("actual_worker_membership_source_bound=true diagnostic_profile_supported=false crypto_failure_hit_observed=false")
}
