package runner

import (
	"bytes"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// ReceiveDispatchSourceObserver sees detached preparation/completion values
// after the original checking mutex is released. It must return promptly and
// cannot grant cache ownership or turn selection into completed core execution.
type ReceiveDispatchSourceObserver interface {
	ObserveReceiveDispatch(journal.ReceiveDispatchRec)
}

func (r *Runner) nextReceiveDispatchSequence() uint64 {
	if r.receiveDispatchSequence == ^uint64(0) {
		r.receiveDispatchExhausted = true
	} else if !r.receiveDispatchExhausted {
		r.receiveDispatchSequence++
	}
	if r.receiveDispatchExhausted {
		return 0
	}
	return r.receiveDispatchSequence
}
func (r *Runner) publishReceiveDispatch(rec *journal.ReceiveDispatchRec) {
	if rec == nil {
		return
	}
	copy := *rec
	copy.Input = bytes.Clone(rec.Input)
	r.d.ReceiveDispatchSources.ObserveReceiveDispatch(copy)
}
func (r *Runner) observeReceivePreparation(q queued, current *receiveContext, decision transport.ReceiveDecision, source transport.ReceivePreparationSource) *journal.ReceiveDispatchRec {
	if r.d.ReceiveDispatchSources == nil {
		return nil
	}
	seq := r.nextReceiveDispatchSequence()
	rec := &journal.ReceiveDispatchRec{Version: journal.ReceiveDispatchSourceVersion, Sequence: seq, Request: seq, EngineRun: r.engineRun, BeforeStep: r.step, Action: "prepare", Via: q.via, Source: source, Decision: uint64(decision), Selection: q.selectionSource, InboxRequest: q.inboxSource, InternalRequest: q.internalSource, Capture: q.capture, Origin: q.origin, StreamRun: q.stream.ObservationRun(), Stream: q.stream.ObservationID(), InputKind: inputlog.Kind(q.in), Mono: uint64(r.d.Clock.Mono()), WallNs: uint64(r.d.Clock.Now().UnixNano())}
	var err error
	rec.Input, err = inputlog.Encode(q.in)
	if err != nil {
		rec.Input, rec.Unavailable = nil, "input_encoding"
	}
	if current == nil || current.scope == nil {
		rec.Unavailable = "scope_unavailable"
	} else {
		rec.Scope = current.scope.ObservationID()
		rec.ContextHash, err = journal.InboxSnapshotDigest(current.snapshot)
		if err != nil {
			rec.Unavailable = "snapshot_encoding"
		}
	}
	if source.WriterRun == "" {
		rec.Unavailable = "unqualified_ledger"
	} else if source.Ledger == 0 || source.Sequence == 0 {
		rec.Unavailable = "preparation_source_missing"
	}
	if q.selectionSource == 0 {
		rec.Unavailable = "selection_source_missing"
	}
	if q.via == viaPeer && q.inboxSource == 0 {
		rec.Unavailable = "inbox_source_missing"
	}
	if q.via == viaInternal && q.internalSource == 0 {
		rec.Unavailable = "internal_source_missing"
	}
	if q.deferred != nil {
		rec.Unavailable = "deferred_input"
	}
	if r.replay.Replayed {
		rec.Unavailable = "replayed_prefix"
	}
	if seq == 0 {
		rec.Unavailable = "metadata_exhausted"
	}
	r.publishReceiveDispatch(rec)
	return rec
}
func (r *Runner) observeReceiveCompletion(original *journal.ReceiveDispatchRec, action string) {
	if original == nil {
		return
	}
	rec := *original
	rec.Sequence = r.nextReceiveDispatchSequence()
	rec.Action = action
	if action == "dispatch" {
		rec.Step = r.step
	}
	rec.Mono, rec.WallNs = uint64(r.d.Clock.Mono()), uint64(r.d.Clock.Now().UnixNano())
	if rec.Sequence == 0 {
		rec.Unavailable = "metadata_exhausted"
	}
	r.publishReceiveDispatch(&rec)
}
