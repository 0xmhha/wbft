package runner

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// AppQueueSourceObserver receives detached application queue metadata after
// appMu is released. Calls can arrive concurrently and out of order; Sequence
// retains the actual mutex order. The observer must return promptly. Mutating
// its input bytes cannot change a queued input or functional journal record.
// This optional hook does not enable functional cache replay or app execution.
type AppQueueSourceObserver interface{ ObserveAppQueueSource(journal.AppQueueRec) }

func (r *Runner) nextAppSourceLocked() uint64 {
	if r.d.AppQueueSources == nil || r.appSourceExhausted || r.appSourceSequence == ^uint64(0) {
		return 0
	}
	return r.appSourceSequence + 1
}

// appendAppLocked preserves the existing queue mutation. Disabled observation
// neither encodes inputs nor retains diagnostic payloads.
func (r *Runner) appendAppLocked(in consensus.Input) *journal.AppQueueRec {
	before := len(r.appQ)
	id := r.nextAppSourceLocked()
	r.appQ = append(r.appQ, queued{in: in, via: viaApp, appSource: id})
	return r.appQueueRecordLocked("append", id, in, 0, 0, before)
}

func (r *Runner) firstHeadSourceLocked() uint64 {
	if r.d.AppQueueSources != nil {
		for _, q := range r.appQ {
			if _, ok := q.in.(consensus.NewHead); ok {
				return q.appSource
			}
		}
	}
	return 0
}

// appQueueRecordLocked is called under appMu, after the actual mutation.
func (r *Runner) appQueueRecordLocked(action string, request uint64, in consensus.Input, engine, step uint64, before int) *journal.AppQueueRec {
	if r.d.AppQueueSources == nil {
		return nil
	}
	if r.appSourceSequence == ^uint64(0) {
		r.appSourceExhausted = true
	} else if !r.appSourceExhausted {
		r.appSourceSequence++
	}
	version := journal.AppQueueSourceVersion
	if action == "close" {
		version = journal.AppQueueCloseSourceVersion
	}
	rec := &journal.AppQueueRec{Version: version, Sequence: r.appSourceSequence, Request: request, EngineRun: engine, Step: step, Action: action, Before: uint64(before), After: uint64(len(r.appQ)), Mono: r.d.Clock.Mono(), WallNs: r.d.Clock.Now().UnixNano()}
	if in != nil {
		rec.InputKind = inputlog.Kind(in)
		var err error
		rec.Input, err = inputlog.Encode(in)
		if err != nil {
			rec.Input, rec.Unavailable = nil, "input_encoding"
		}
	}
	if r.appSourceExhausted {
		rec.Sequence, rec.Unavailable = 0, "metadata_exhausted"
	}
	return rec
}

func (r *Runner) publishAppQueue(rec *journal.AppQueueRec) {
	if rec != nil {
		r.d.AppQueueSources.ObserveAppQueueSource(*rec)
	}
}

// closeAppQueue runs only after the final worker joins. Unlike Stop's clear,
// it is a terminal lifecycle operation and must not invent another core Stop.
func (r *Runner) closeAppQueue() {
	r.appMu.Lock()
	if r.appQueueClosed {
		r.appMu.Unlock()
		return
	}
	r.appQueueClosed = true
	before := len(r.appQ)
	r.appQ, r.headNote = nil, nil
	observation := r.appQueueRecordLocked("close", 0, nil, r.engineRun, r.step, before)
	if observation != nil && observation.Unavailable == "" && (r.engineRun == 0 || r.step == 0) {
		observation.Unavailable = "stop_source_missing"
	}
	r.appMu.Unlock()
	r.publishAppQueue(observation)
}
