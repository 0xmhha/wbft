package runner

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// InternalSourceObserver runs on the original consensus loop after a queue
// operation. Input bytes are detached; observers must return promptly. Nil
// neither encodes inputs nor retains diagnostic payloads.
type InternalSourceObserver interface{ ObserveInternalSource(journal.InternalRec) }

func (r *Runner) internalRecord(action string, q queued, origin string, output uint64, before int) *journal.InternalRec {
	if r.d.InternalSources == nil {
		return nil
	}
	if r.internalSourceSequence == ^uint64(0) {
		r.internalSourceExhausted = true
	} else if !r.internalSourceExhausted {
		r.internalSourceSequence++
	}
	rec := &journal.InternalRec{Version: journal.InternalSourceVersion, Sequence: r.internalSourceSequence, Request: q.internalSource, EngineRun: r.engineRun, Action: action, Origin: origin, Output: output, Before: uint64(before), After: uint64(len(r.internal)), Mono: uint64(r.d.Clock.Mono()), WallNs: uint64(r.d.Clock.Now().UnixNano())}
	if action == "append" || action == "clear" || action == "dispatch" {
		rec.Step = r.step
	}
	if action == "append" {
		rec.Request = rec.Sequence
	}
	if action == "dispatch" || action == "discard" {
		rec.Before, rec.After = 0, 0
	}
	if q.in != nil {
		rec.InputKind = inputlog.Kind(q.in)
		var err error
		rec.Input, err = inputlog.Encode(q.in)
		if err != nil {
			rec.Input, rec.Unavailable = nil, "input_encoding"
		}
	}
	if origin == "replay" {
		rec.Step, rec.Unavailable = 0, "replay_prefix"
	}
	if origin == "signer_missing" || origin == "refusal" || origin == "outbound" {
		rec.Unavailable = "signer_state"
	}
	if action == "discard" {
		rec.Unavailable = "dispatch_deduplicated"
	}
	if (action == "dispatch" || action == "pop") && q.internalSource == 0 {
		rec.Unavailable = "dispatch_source_missing"
	}
	if r.internalSourceExhausted {
		rec.Sequence, rec.Unavailable = 0, "metadata_exhausted"
		if action == "append" {
			rec.Request = 0
		}
	}
	return rec
}

func (r *Runner) publishInternal(rec *journal.InternalRec) {
	if rec != nil {
		r.d.InternalSources.ObserveInternalSource(*rec)
	}
}

func (r *Runner) appendInternal(in consensus.Input, origin string, output uint64) {
	before := len(r.internal)
	q := queued{in: in, via: viaInternal}
	if r.d.InternalSources != nil && !r.internalSourceExhausted && r.internalSourceSequence != ^uint64(0) {
		q.internalSource = r.internalSourceSequence + 1
	}
	r.internal = append(r.internal, q)
	r.publishInternal(r.internalRecord("append", q, origin, output, before))
}

func (r *Runner) clearInternal(action string) {
	before := len(r.internal)
	r.internal = nil
	r.publishInternal(r.internalRecord(action, queued{}, "", 0, before))
}

func (r *Runner) dispatchInternal(q queued, action string) {
	if q.via == viaInternal {
		r.publishInternal(r.internalRecord(action, q, "", 0, 0))
	}
}
