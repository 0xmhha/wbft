package node

import (
	"slices"

	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

var _ transport.ReceiveFailureObserver = (*sessionFrameRecorder)(nil)
var _ runner.InboxFailureSourceObserver = (*sessionFrameRecorder)(nil)
var _ runner.ReceiveFailureDiagnosticObserver = (*sessionFrameRecorder)(nil)

// CoreDeclaration returns the recorder's detached constructor-time snapshot.
// A writer without a declaration cannot enable the coordinated profile.
func (f *sessionFrameRecorder) CoreDeclaration() journal.CoreOptions {
	if f.coreDeclaration == nil {
		return journal.CoreOptions{}
	}
	return f.coreDeclaration.Copy()
}

// ObserveReceiveFailure retains the cache's original mutex sequence and frozen
// namespace. Callback timestamps do not replace the original mutation order.
// This adapter alone does not enable the staged runtime diagnostic profile.
func (f *sessionFrameRecorder) ObserveReceiveFailure(source transport.ReceiveFailureEvent) {
	f.jw.Put(journal.Record{Body: &journal.ReceiveFailureCacheRec{
		Version: journal.ReceiveFailureRecordVersion, Transition: source,
		Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano(),
	}})
}

// ObserveInboxFailureHit preserves the separate lookup/original references.
// It never emits an ordinary inbox check, signer call or accepted input.
func (f *sessionFrameRecorder) ObserveInboxFailureHit(source journal.InboxFailureHitRec) {
	// The writer may encode asynchronously. Keep the detached diagnostic value
	// independent of caller-owned buffers without changing or repairing its shape.
	source.Source.Payload = slices.Clone(source.Source.Payload)
	source.Source.Order = slices.Clone(source.Source.Order)
	source.Source.Candidates = slices.Clone(source.Source.Candidates)
	f.jw.Put(journal.Record{Body: &source})
}
