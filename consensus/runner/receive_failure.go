package runner

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

func failurePublicationPhase(phase string) transport.ReceiveFailurePhase {
	switch phase {
	case snapshotStart:
		return transport.ReceiveFailureStart
	case snapshotStep:
		return transport.ReceiveFailureStep
	case snapshotReplay:
		return transport.ReceiveFailureReplay
	default:
		return 0
	}
}

// publishFailureSnapshot runs on the consensus loop. The exact immutable
// envelope owns one failure context, even when validation contents are equal.
func (r *Runner) publishFailureSnapshot(snapshot *consensus.Snapshot, phase string) {
	publication := &snapshotPublication{snapshot: snapshot, owner: snapshotOwner{engine: r.engineRun, step: r.step, phase: phase, replayed: r.replay.Replayed}}
	current := r.updateReceiveContext(snapshot)
	digest, err := journal.InboxSnapshotDigest(snapshot)
	if current != nil && snapshot != nil && snapshot.Running && sameReceiveContext(current.snapshot, snapshot) && failurePublicationPhase(phase) != 0 && err == nil {
		publication.failureSource = transport.ReceiveFailureSource{EngineRun: publication.owner.engine, SnapshotStep: publication.owner.step, SnapshotPhase: failurePublicationPhase(phase), SnapshotHash: digest}
		publication.failureValidation = current
		publication.failureContext = r.receiveFailures.BeginContext(current.scope, failurePublicationSource(publication))
	} else {
		r.receiveFailures.Invalidate()
	}
	r.snap.current.Store(publication)
}

func failurePublicationSource(publication *snapshotPublication) transport.ReceiveFailureSource {
	if publication == nil {
		return transport.ReceiveFailureSource{}
	}
	return publication.failureSource
}

// Request is allocated under the inbox mutex at the original append. Neither
// a worker nor a later publication can relabel the retained failure's source.
// These coordinates still require a supported diagnostic producer/checker and
// frozen writer namespace before they can become available evidence.
func failureWorkerSource(publication *snapshotPublication, request uint64) transport.ReceiveFailureSource {
	source := failurePublicationSource(publication)
	source.WorkerRequest = request
	return source
}

func (r *Runner) currentFailureContext(publication *snapshotPublication) *transport.ReceiveFailureContext {
	if r.receiveFailures == nil || publication == nil || publication.failureContext == nil || r.snap.loadPublication() != publication {
		return nil
	}
	current := r.receiveContext.Load()
	if current == nil || current != publication.failureValidation || !current.scope.Active() || !sameReceiveContext(current.snapshot, publication.snapshot) {
		return nil
	}
	return publication.failureContext
}

func receiveFailureClass(failure consensus.RecoveryFailure) (transport.ReceiveFailureClass, bool) {
	switch failure {
	case consensus.RecoverySignature:
		return transport.ReceiveSignatureFailure, true
	case consensus.RecoveryMembership:
		return transport.ReceiveMembershipFailure, true
	default:
		return 0, false
	}
}

func receiveFailureReason(class transport.ReceiveFailureClass) string {
	switch class {
	case transport.ReceiveSignatureFailure:
		return "signature"
	case transport.ReceiveMembershipFailure:
		return "membership"
	default:
		return ""
	}
}
