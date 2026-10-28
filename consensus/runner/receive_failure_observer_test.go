package runner

import (
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type failureHitObservations struct {
	records []journal.InboxFailureHitRec
	inspect func()
}

func (o *failureHitObservations) ObserveInboxFailureHit(rec journal.InboxFailureHitRec) {
	if o.inspect != nil {
		o.inspect()
	}
	o.records = append(o.records, rec)
}

// This is a normal owned signature checked against another local authority
// context. No network packet or signature bytes are changed or transmitted.
func TestReceiveFailureActualHitHasSeparateUnlockedInboxSource(t *testing.T) {
	members, owned := newKeys(t, 4), newKeys(t, 5)
	n := newTNode(t, members, 1)
	n.noJournal = true
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	n.receiveFailureCache = &transport.ReceiveFailureOptions{Entries: 2}
	o := new(failureHitObservations)
	n.inboxFailureSources = o
	o.inspect = func() {
		if !n.r.inbox.mu.TryLock() {
			t.Fatal("failure hit observer called while inbox mutex was held")
		}
		n.r.inbox.mu.Unlock()
	}
	checks, hits := 0, 0
	n.receiveRecoveryChecked = func(_ codec.Code, phase consensus.RecoveryFailure) {
		if phase != consensus.RecoveryMembership {
			t.Error("normal local authority mismatch changed class")
		}
		checks++
	}
	n.receiveFailureHit = func(_ uint64, _ transport.ReceiveFailureClass) { hits++ }
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
		t.Fatal("fixture was not a valid owned signature", err)
	}
	in := transportInbound(members, 0, codec.CodePrepare, raw, n.clock.now)
	publication := n.r.snap.loadPublication()
	digest, err := journal.InboxSnapshotDigest(publication.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	feed := func() uint64 {
		t.Helper()
		if !n.r.Receiver().Offer(in) {
			t.Fatal("normal local input refused")
		}
		request := n.r.inbox.sourceSequence
		if !n.r.inbox.checkOne(true) {
			t.Fatal("original local request did not reach its worker")
		}
		return request
	}
	first := feed()
	if checks != 1 || hits != 0 || len(o.records) != 0 {
		t.Fatal("actual first failure was incorrectly emitted as reuse")
	}
	for expected := 1; expected <= 2; expected++ {
		request := feed()
		if request <= first || checks != 1 || hits != expected || len(o.records) != expected {
			t.Fatal("reuse executed recovery or lost its distinct observation")
		}
		rec := o.records[expected-1]
		source := rec.Source
		if rec.Version != journal.ReceiveFailureRecordVersion || rec.Class != transport.ReceiveMembershipFailure || rec.Unavailable != "failure_reference_unavailable" || source.Unavailable != "" {
			t.Fatal("NoTrace was falsely promoted to a qualified failure namespace", rec)
		}
		if source.Action != "failure_hit" || source.Result != "membership" || source.Request != request || source.Sequence != request+1 || source.Signer != (types.Address{}) || len(source.Payload) != 0 {
			t.Fatal("hit lost original inbox mutex order or became a signer/check result", source)
		}
		if source.SnapshotEngine != publication.owner.engine || source.SnapshotStep != publication.owner.step || source.SnapshotPhase != publication.owner.phase || source.SnapshotContextHash != digest {
			t.Fatal("later metadata relabeled the original worker publication")
		}
		if rec.Lookup.Run != "" || rec.Original.Run != "" || rec.Lookup.Cache == 0 || rec.Lookup.Cache != rec.Original.Cache || rec.Original.Sequence == 0 || rec.Lookup.Sequence <= rec.Original.Sequence {
			t.Fatal("separate lookup lost the earlier actual failure reference", rec)
		}
		if expected > 1 && rec.Original != o.records[0].Original {
			t.Fatal("a later hit replaced the actual first failure's reference")
		}
		// Mutate only detached observer metadata. No changed value reaches a
		// receiver or verifier, and the original peer order must remain intact.
		if len(source.Order) == 0 {
			t.Fatal("actual peer order missing")
		}
		source.Order[0][0] ^= 1
		if n.r.inbox.order[0] != in.Peer {
			t.Fatal("observer metadata retained the runtime peer-order slice")
		}
	}
	current := n.r.receiveContext.Load()
	if n.r.receiveCache.Known(current.scope, in.Code, in.Payload) || n.r.receiveCache.Recent(current.scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("a failed hit became accepted cache authority")
	}
	t.Log("actual_membership_hit_observer=true diagnostic_profile_supported=false crypto_failure_hit_observed=false")
}

func TestReceiveFailureHitObserverRequiresExplicitOption(t *testing.T) {
	if r, err := New(Config{}, Deps{InboxFailureSources: new(failureHitObservations)}); err == nil || !strings.Contains(err.Error(), "failure hit observations require an explicit failure cache") || r != nil {
		t.Fatal("failure hit observer silently enabled an absent cache")
	}
}
