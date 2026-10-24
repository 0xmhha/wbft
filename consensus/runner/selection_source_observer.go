package runner

import (
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// SelectionSourceObserver sees detached original conditional probes and the
// selected input after all lane mutexes are released. It must return promptly.
// This hook neither merges those mutexes nor draws additional randomness.
type SelectionSourceObserver interface{ ObserveInputSelection(journal.SelectionRec) }

func (r *Runner) newSelection() *journal.SelectionRec {
	if r.d.SelectionSources == nil {
		return nil
	}
	p := journal.InputProbe{State: "not_probed"}
	rec := &journal.SelectionRec{Version: journal.SelectionSourceVersion, EngineRun: r.engineRun, Step: r.step, Action: "select", Internal: p, App: p, Timer: p, Inbox: p, NextHeight: "not_probed"}
	if r.d.ManualProcessing != nil {
		rec.Unavailable = "manual_processing"
	}
	return rec
}
func inputProbe(ready bool, sequence, mono uint64) journal.InputProbe {
	state := "empty"
	if ready {
		state = "ready"
	}
	return journal.InputProbe{State: state, Sequence: sequence, Mono: mono}
}
func (r *Runner) selectionProbe(rec *journal.SelectionRec, lane string, ready bool, sequence uint64) {
	if rec == nil {
		return
	}
	p := inputProbe(ready, sequence, uint64(r.d.Clock.Mono()))
	present := false
	switch lane {
	case "internal":
		rec.Internal = p
		present = r.d.InternalSources != nil
	case "app":
		rec.App = p
		present = r.d.AppQueueSources != nil
	}
	if !present && rec.Unavailable == "" {
		rec.Unavailable = "lane_source_missing"
	}
}
func (r *Runner) observeSelection(rec *journal.SelectionRec, q queued) uint64 {
	if rec == nil {
		return 0
	}
	if r.selectionSourceSequence == ^uint64(0) {
		r.selectionSourceExhausted = true
	} else if !r.selectionSourceExhausted {
		r.selectionSourceSequence++
	}
	rec.Sequence = r.selectionSourceSequence
	if rec.Action == "select" {
		rec.Selection = rec.Sequence
	}
	if q.in != nil {
		rec.InputKind = inputlog.Kind(q.in)
		var err error
		rec.Input, err = inputlog.Encode(q.in)
		if err != nil {
			rec.Input, rec.Unavailable = nil, "input_encoding"
		}
	}
	rec.Mono, rec.WallNs = uint64(r.d.Clock.Mono()), uint64(r.d.Clock.Now().UnixNano())
	if r.selectionSourceExhausted {
		rec.Sequence, rec.Unavailable = 0, "metadata_exhausted"
		if rec.Action == "select" {
			rec.Selection = 0
		}
	}
	id := rec.Selection
	r.d.SelectionSources.ObserveInputSelection(*rec)
	return id
}
func (r *Runner) finishSelection(rec *journal.SelectionRec, lane string, source uint64, q queued, ok bool) (queued, bool) {
	if rec != nil {
		rec.Lane, rec.Source = lane, source
		if !ok {
			rec.Lane, rec.Source = "none", 0
		}
		if ok && source == 0 && rec.Unavailable == "" {
			rec.Unavailable = "lane_source_missing"
		}
		q.selectionSource = r.observeSelection(rec, q)
	}
	return q, ok
}
func (r *Runner) dispatchSelection(q queued, action string) {
	if r.d.SelectionSources == nil {
		return
	}
	rec := &journal.SelectionRec{Version: journal.SelectionSourceVersion, EngineRun: r.engineRun, Selection: q.selectionSource, Action: action}
	if action == "dispatch" {
		rec.Step = r.step
	}
	if q.selectionSource == 0 {
		rec.Unavailable = "dispatch_source_missing"
	} else if action == "discard" {
		rec.Unavailable = "dispatch_deduplicated"
	}
	r.observeSelection(rec, q)
}
