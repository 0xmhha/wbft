package runner

import (
	"bytes"
	"slices"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// InboxSourceObserver receives detached metadata after the inbox mutex is
// released. Delivery may be reordered; Sequence retains actual mutex order.
// Observers must return promptly and never become functional cache authority.
type InboxSourceObserver interface{ ObserveInboxSource(journal.InboxRec) }

type inboxEntry struct {
	in      transport.Inbound
	request uint64
}

// inboxSourceLocked never consults the loop's mutable engine/step. Only the
// consensus-loop take/clear callers attach their own dispatch coordinates.
func (b *inbox) nextSourceSequenceLocked() uint64 {
	if b.sourceSequence == ^uint64(0) {
		b.sourceExhausted = true
	} else if !b.sourceExhausted {
		b.sourceSequence++
	}
	if b.sourceExhausted {
		return 0
	}
	return b.sourceSequence
}

func (b *inbox) inboxSourceLocked(action string, entry inboxEntry) *journal.InboxRec {
	if b.r.d.InboxSources == nil {
		return nil
	}
	return b.sourceLocked(action, entry)
}

// sourceLocked allocates one identity in the shared inbox mutex order. Callers
// choose their record kind; a cached failure is never published as Inbox/check.
func (b *inbox) sourceLocked(action string, entry inboxEntry) *journal.InboxRec {
	sequence := b.nextSourceSequenceLocked()
	in := entry.in
	rec := &journal.InboxRec{Version: journal.InboxSourceVersion, Sequence: sequence, Request: entry.request, Action: action, Peer: in.Peer, Code: in.Code, Capture: in.Capture, RecvMono: uint64(in.RecvMono), Origin: in.Origin, StreamRun: in.Stream.ObservationRun(), Stream: in.Stream.ObservationID(), Order: slices.Clone(b.order), WorkerCursor: uint64(b.wIdx), ConsensusCursor: uint64(b.cIdx), Mono: uint64(b.r.d.Clock.Mono()), WallNs: uint64(b.r.d.Clock.Now().UnixNano())}
	if action == "append" {
		rec.Request, rec.Payload = rec.Sequence, bytes.Clone(in.Payload)
	}
	if b.sourceExhausted {
		rec.Sequence, rec.Unavailable = 0, "metadata_exhausted"
		if action == "append" {
			rec.Request = 0
		}
	}
	return rec
}

func copyInboxSnapshotSource(rec *journal.InboxRec, snapshot journal.InboxRec) {
	rec.SnapshotEngine, rec.SnapshotStep, rec.SnapshotPhase = snapshot.SnapshotEngine, snapshot.SnapshotStep, snapshot.SnapshotPhase
	rec.SnapshotReplayed, rec.SnapshotContextHash = snapshot.SnapshotReplayed, snapshot.SnapshotContextHash
	if rec.Unavailable == "" {
		rec.Unavailable = snapshot.Unavailable
	}
}

func inboxSnapshotSource(publication *snapshotPublication) journal.InboxRec {
	if publication == nil {
		return journal.InboxRec{Unavailable: "snapshot_unavailable"}
	}
	o := publication.owner
	rec := journal.InboxRec{SnapshotEngine: o.engine, SnapshotStep: o.step, SnapshotPhase: o.phase}
	if o.replayed {
		rec.SnapshotReplayed = 1
	}
	digest, err := journal.InboxSnapshotDigest(publication.snapshot)
	if err != nil {
		rec.Unavailable = "snapshot_encoding"
	} else {
		rec.SnapshotContextHash = digest
	}
	return rec
}

func (b *inbox) checkSourceLocked(entry inboxEntry, result string, snapshot journal.InboxRec) *journal.InboxRec {
	rec := b.inboxSourceLocked("check", entry)
	if rec != nil {
		rec.Result = result
		copyInboxSnapshotSource(rec, snapshot)
	}
	return rec
}

func (b *inbox) rejectedSource(entry inboxEntry, result string, snapshot journal.InboxRec) {
	if b.r.d.InboxSources == nil {
		return
	}
	b.mu.Lock()
	rec := b.checkSourceLocked(entry, result, snapshot)
	b.mu.Unlock()
	b.publishInbox(rec)
}

func (b *inbox) publishInbox(rec *journal.InboxRec) {
	if rec != nil {
		b.r.d.InboxSources.ObserveInboxSource(*rec)
	}
}

// dispatchSource runs on the consensus loop. Selection alone is not execution:
// the accepted-input ledger may discard a taken input before a core step.
func (b *inbox) dispatchSource(q queued, action string) {
	if b.r.d.InboxSources == nil || q.via != viaPeer || q.deferred != nil {
		return
	}
	m, ok := q.in.(consensus.Message)
	if !ok {
		return
	}
	entry := inboxEntry{in: transport.Inbound{Peer: m.Peer, Code: uint64(m.Code), Payload: m.Payload, RecvMono: m.RecvMono, Capture: q.capture, Origin: q.origin, Stream: q.stream}, request: q.inboxSource}
	b.mu.Lock()
	rec := b.inboxSourceLocked(action, entry)
	rec.EngineRun = b.r.engineRun
	if action == "dispatch" {
		rec.Step = b.r.step
	}
	if rec.Unavailable == "" {
		if q.inboxSource == 0 {
			rec.Unavailable = "dispatch_source_missing"
		} else if action == "discard" {
			rec.Unavailable = "dispatch_deduplicated"
		}
	}
	b.mu.Unlock()
	b.publishInbox(rec)
}
