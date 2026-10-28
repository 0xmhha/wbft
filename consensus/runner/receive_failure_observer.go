package runner

import (
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// InboxFailureSourceObserver receives detached evidence of a reused failure,
// never an executed recovery or successful signer. Like the ordinary inbox
// observer, callbacks run outside the mutex and may arrive out of order.
// This observer alone does not enable a supported diagnostic/replay profile.
type InboxFailureSourceObserver interface {
	ObserveInboxFailureHit(journal.InboxFailureHitRec)
}

func qualifiedReceiveFailureRef(ref transport.ReceiveFailureRef) bool {
	return ref.Run != "" && ref.Cache != 0 && ref.Sequence != 0
}

func (b *inbox) publishFailureHit(entry inboxEntry, hit transport.ReceiveFailureHit, publication *snapshotPublication) {
	observer := b.r.d.InboxFailureSources
	if observer == nil {
		return
	}
	snapshot := inboxSnapshotSource(publication)
	b.mu.Lock()
	source := b.sourceLocked("failure_hit", entry)
	source.Result = receiveFailureReason(hit.Class)
	copyInboxSnapshotSource(source, snapshot)
	b.mu.Unlock()
	rec := journal.InboxFailureHitRec{Version: journal.ReceiveFailureRecordVersion, Source: *source, Lookup: hit.Lookup, Original: hit.Reference, Class: hit.Class}
	if !qualifiedReceiveFailureRef(rec.Lookup) || !qualifiedReceiveFailureRef(rec.Original) {
		rec.Unavailable = "failure_reference_unavailable"
	}
	observer.ObserveInboxFailureHit(rec)
}
