package runner

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func TestSnapshotPublicationEqualContentsRetainDifferentOwners(t *testing.T) {
	var published publishedSnapshot
	if published.Load() != nil || published.loadPublication() != nil {
		t.Fatal("zero holder invented a snapshot")
	}
	snapshot := &consensus.Snapshot{Running: true, View: view(10, 0)}
	firstOwner := snapshotOwner{engine: 1, step: 3, phase: snapshotStep}
	published.publish(snapshot, firstOwner)
	first := published.loadPublication()
	published.publish(snapshot, snapshotOwner{engine: 1, step: 4, phase: snapshotStep})
	second := published.loadPublication()
	if first == second || first.snapshot != second.snapshot || first.owner != firstOwner || second.owner.step != 4 || published.Load() != snapshot {
		t.Fatal("equal contents erased publication provenance")
	}
	published.publish(&consensus.Snapshot{}, snapshotOwner{engine: 1, step: 5, phase: snapshotStopped})
	published.publish(snapshot, snapshotOwner{engine: 2, step: 1, phase: snapshotStart})
	if first.owner != firstOwner || first.snapshot != snapshot || second.owner.engine != 1 || second.owner.step != 4 {
		t.Fatal("later publications rewrote retained ownership")
	}
}

func TestSnapshotPublicationConcurrentReadersRetainCoherentOwner(t *testing.T) {
	var published publishedSnapshot
	const count = 2000
	var readers sync.WaitGroup
	start, done := make(chan struct{}), make(chan struct{})
	failures := make(chan string, 4)
	for range 4 {
		readers.Go(func() {
			<-start
			for {
				if p := published.loadPublication(); p != nil {
					// The view encodes this immutable fixture's publication coordinate.
					// Readers never consult the separately mutable writer variables.
					if p.snapshot.View.Cmp(view(p.owner.engine, p.owner.step)) != 0 || p.owner.phase != snapshotStep {
						failures <- fmt.Sprintf("mixed publication: %+v", p.owner)
						return
					}
				}
				select {
				case <-done:
					return
				default:
				}
			}
		})
	}
	close(start)
	for i := uint64(1); i <= count; i++ {
		published.publish(&consensus.Snapshot{Running: true, View: view(i, i+1)}, snapshotOwner{engine: i, step: i + 1, phase: snapshotStep})
	}
	close(done)
	readers.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestSnapshotPublicationActualLifecycleAndRestoredPrefix(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	t.Cleanup(func() {
		if err := n.r.Close(); err != nil {
			t.Error(err)
		}
		if err := n.log.Close(); err != nil {
			t.Error(err)
		}
	})
	first := n.r.snap.loadPublication()
	if first == nil || first.owner.engine != 1 || first.owner.step != n.r.step || first.owner.replayed || n.r.Snapshot() != first.snapshot {
		t.Fatal("fresh publication owner missing")
	}
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, b)
	prepared := n.r.snap.loadPublication()
	if prepared == first || prepared.owner.phase != snapshotStep || prepared.owner.engine != 1 || prepared.owner.step != n.r.step || prepared.snapshot.State != consensus.Prepared {
		t.Fatal("actual completed step publication missing")
	}
	retainedOwner := prepared.owner
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	stopped := n.r.snap.loadPublication()
	if stopped.snapshot.Running || stopped.owner.phase != snapshotStopped || stopped.owner.engine != 1 || stopped.owner.step != retainedOwner.step+1 || n.r.Snapshot() != stopped.snapshot {
		t.Fatal("synthetic stopped publication mislabeled")
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	restored := n.r.snap.loadPublication()
	if !n.r.LastReplay().Replayed || restored.owner.phase != snapshotReplay || !restored.owner.replayed || restored.owner.engine != 2 || restored.owner.step != n.r.step {
		t.Fatal("restored prefix became fresh live evidence")
	}
	n.r.PeerConnected(k.addrs[2])
	n.r.Pump()
	later := n.r.snap.loadPublication()
	if later.owner.phase != snapshotStep || !later.owner.replayed || later.owner.engine != 2 || later.owner.step != n.r.step || later.owner.step <= restored.owner.step {
		t.Fatal("later restored-run publication lost its prefix label")
	}
	if prepared.owner != retainedOwner || prepared.snapshot.State != consensus.Prepared || first.owner.engine != 1 || stopped.snapshot.Running {
		t.Fatal("operator Stop/Start changed an earlier retained publication")
	}
}

func TestSnapshotPublicationConstructionAndFreshStart(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	r, err := New(Config{Core: consensus.Options{Config: n.opts.Config}, Manual: true}, Deps{Chain: n.chain, App: n.app, Clock: n.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	initial := r.snap.loadPublication()
	if initial == nil || initial.owner != (snapshotOwner{phase: snapshotInitial}) || initial.snapshot == nil || initial.snapshot.Running || r.Snapshot() != initial.snapshot {
		t.Fatal("constructor did not publish its original empty snapshot")
	}
	if err := r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	started := r.snap.loadPublication()
	if started.owner != (snapshotOwner{engine: 1, step: 1, phase: snapshotStart}) || !started.snapshot.Running {
		t.Fatal("fresh Start publication mislabeled")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	if p := r.snap.loadPublication(); p.owner != (snapshotOwner{engine: 2, step: 1, phase: snapshotStart}) || !p.snapshot.Running {
		t.Fatal("fresh operator restart reused the earlier owner")
	}
}

func BenchmarkSnapshotPublication(b *testing.B) {
	var published publishedSnapshot
	snapshot := &consensus.Snapshot{Running: true, View: types.View{}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		published.publish(snapshot, snapshotOwner{engine: 1, step: uint64(i + 1), phase: snapshotStep})
		_ = published.loadPublication()
	}
}
