package runner

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type inboxObservations struct {
	observations []journal.InboxRec
	inspect      func()
	alter        bool
}

func (o *inboxObservations) ObserveInboxSource(source journal.InboxRec) {
	if o.inspect != nil {
		o.inspect()
	}
	detached := source
	detached.Payload = bytes.Clone(source.Payload)
	detached.Order = slices.Clone(source.Order)
	detached.Candidates = slices.Clone(source.Candidates)
	o.observations = append(o.observations, detached)
	if o.alter {
		// Only observer-owned metadata changes. No modified input reaches a runner.
		if len(source.Payload) > 0 {
			source.Payload[0] ^= 1
		}
		if len(source.Order) > 0 {
			source.Order[0][0] ^= 1
		}
		if len(source.Candidates) > 0 {
			source.Candidates[0][0] ^= 1
		}
	}
}

func TestInboxSourcesNormalWorkerCursorAndUnlockedDetachedCallback(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	o := &inboxObservations{alter: true}
	n.inboxSources = o
	o.inspect = func() {
		if !n.r.inbox.mu.TryLock() {
			t.Fatal("observer called with inbox mutex held")
		}
		n.r.inbox.mu.Unlock()
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
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
	start := len(o.observations)
	for _, peer := range []int{0, 2} {
		in := transportInbound(k, peer, codec.CodePrepare, k.vote(t, peer, codec.CodePrepare, view(10, 0), b), n.clock.now)
		if !n.r.Receiver().Offer(in) {
			t.Fatal("normal signed vote refused")
		}
	}
	if !n.r.inbox.checkOne(false) || !n.r.inbox.checkOne(false) || n.r.inbox.checkOne(false) {
		t.Fatal("normal worker queue did not drain exactly once")
	}
	dequeues := []journal.InboxRec{}
	for _, source := range o.observations[start:] {
		if source.Action == "dequeue" {
			dequeues = append(dequeues, source)
		}
	}
	if len(dequeues) != 2 || dequeues[0].Manual != 0 || dequeues[0].Peer != k.addrs[2] || dequeues[0].WorkerCursor != 1 || dequeues[1].Peer != k.addrs[0] || dequeues[1].WorkerCursor != 0 || len(dequeues[1].Candidates) != 1 {
		t.Fatal("worker cursor used global order instead of active candidates", dequeues)
	}
	n.r.Pump()
	if n.r.Vars().State != consensus.Prepared || len(n.net.own(codec.CodeCommit)) != 1 {
		t.Fatal("detached observer changed normal signature or slot processing")
	}
	for _, source := range o.observations {
		if source.Sequence == 0 || source.Unavailable != "" {
			t.Fatal("normal source unavailable", source)
		}
		if source.Action == "check" && (source.SnapshotEngine != 1 || source.SnapshotStep == 0 || source.SnapshotPhase == "" || source.SnapshotReplayed != 0) {
			t.Fatal("actual checking publication owner missing", source)
		}
	}
}

func TestInboxSourcesMetadataExhaustionStaysUnavailable(t *testing.T) {
	r := &Runner{d: Deps{Clock: &manualClock{}, InboxSources: new(inboxObservations)}}
	r.inbox.init(r)
	b := &r.inbox
	b.mu.Lock()
	b.sourceSequence = ^uint64(0)
	first := b.inboxSourceLocked("append", inboxEntry{})
	b.sourceSequence = 1
	second := b.inboxSourceLocked("append", inboxEntry{})
	b.mu.Unlock()
	if first.Sequence != 0 || first.Request != 0 || first.Unavailable != "metadata_exhausted" || second.Sequence != 0 || second.Request != 0 || second.Unavailable != "metadata_exhausted" {
		t.Fatal("metadata exhaustion silently recovered", first, second)
	}
}

type concurrentInboxSources chan journal.InboxRec

func (o concurrentInboxSources) ObserveInboxSource(source journal.InboxRec) {
	select {
	case o <- source:
	default:
	}
}

func TestInboxSourcesNormalConcurrentWorkersAndOperatorRestart(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	clock := SystemClock()
	n.chain.clock = clock
	observed := make(concurrentInboxSources, 256)
	r, err := New(Config{Core: n.opts, Workers: 2}, Deps{Chain: n.chain, App: n.app, Clock: clock, Signer: mustSigner(t, k, 1), InboxSources: observed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	for _, in := range []struct {
		peer    int
		code    codec.Code
		payload []byte
	}{{0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b)}, {2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), b)}} {
		if !r.Receiver().Offer(transportInbound(k, in.peer, in.code, in.payload, clock.Mono())) {
			t.Fatal("normal signed input refused")
		}
	}
	retained := []journal.InboxRec{}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(retained) < 2 {
		select {
		case source := <-observed:
			if source.Action == "check" {
				retained = append(retained, source)
			}
		case <-deadline.C:
			t.Fatal("normal concurrent checks did not complete")
		}
	}
	for _, source := range retained {
		if source.Unavailable != "" || source.Result != "insert" || source.SnapshotEngine != 1 || source.SnapshotStep == 0 || source.SnapshotReplayed != 0 {
			t.Fatal("worker did not retain its actual checking publication", source)
		}
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	if current := r.snap.loadPublication(); current.owner.engine != 2 || current.owner.replayed {
		t.Fatal("ordinary new engine owner missing")
	}
	for _, source := range retained {
		if source.SnapshotEngine != 1 {
			t.Fatal("later engine relabeled retained worker metadata")
		}
	}
}
