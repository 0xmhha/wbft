package runner

import (
	"sync/atomic"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
)

// snapshotOwner identifies a publication, not a receive-cache validation scope.
// Equal snapshot contents may belong to different completed steps. A restored
// prefix retains its label throughout the run; its absent live steps cannot be
// reconstructed from a publication owner.
type snapshotOwner struct {
	engine, step uint64
	phase        string
	replayed     bool
}

const (
	snapshotInitial = "initial"
	snapshotStart   = "start"
	snapshotStep    = "step"
	snapshotReplay  = "replay"
	snapshotStopped = "stopped"
)

// snapshotPublication is immutable once published. Retaining it retains the
// exact snapshot and its original owner across later steps and engine controls.
// The synthetic initial/stopped snapshots are distinct from core snapshots.
type snapshotPublication struct {
	snapshot          *consensus.Snapshot
	owner             snapshotOwner
	failureContext    *transport.ReceiveFailureContext
	failureValidation *receiveContext
	failureSource     transport.ReceiveFailureSource
}

// publishedSnapshot keeps ownership coherent without a second atomic read or
// access to the loop's mutable engine/step fields from a receive worker.
type publishedSnapshot struct {
	current atomic.Pointer[snapshotPublication]
}

func (p *publishedSnapshot) Load() *consensus.Snapshot {
	if publication := p.loadPublication(); publication != nil {
		return publication.snapshot
	}
	return nil
}

func (p *publishedSnapshot) loadPublication() *snapshotPublication { return p.current.Load() }

func (p *publishedSnapshot) publish(snapshot *consensus.Snapshot, owner snapshotOwner) {
	p.current.Store(&snapshotPublication{snapshot: snapshot, owner: owner})
}

// publishSnapshot runs only on the consensus loop (or during construction).
// Consumers load one immutable envelope and never infer its owner from the
// currently running engine or an equivalent validation context.
func (r *Runner) publishSnapshot(snapshot *consensus.Snapshot, phase string) {
	if r.receiveFailures != nil {
		r.publishFailureSnapshot(snapshot, phase)
		return
	}
	r.snap.publish(snapshot, snapshotOwner{engine: r.engineRun, step: r.step, phase: phase, replayed: r.replay.Replayed})
}
