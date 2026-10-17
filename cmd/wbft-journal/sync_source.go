package main

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

type syncSource struct {
	seq      uint64
	position wal.Position
	record   *journal.SyncRec
}

type syncRun struct {
	node                                                                       string
	version, declaration, requests, operations, maxRequest, maxOperation, last uint64
	complete                                                                   bool
	inputs                                                                     map[uint64]syncSource
	handled                                                                    map[uint64]*journal.SyncRec
}

// Logical identities need not follow journal order: a concurrent callback can
// enqueue its request after a later callback or its actual processing record.
func (w *r01Writer) indexSync(rec journal.Record, pos wal.Position) {
	if w.syncErr != nil {
		return
	}
	if s, ok := rec.Body.(*journal.SegmentRec); ok {
		if w.syncSources == nil {
			w.syncSources = map[string]*syncRun{}
		}
		old := w.syncSources[s.Run]
		if w.syncRunID != s.Run && old != nil && (old.version != 0 || s.Core.SyncTrace != 0) {
			w.syncErr = fmt.Errorf("sync writer run reappeared")
			return
		}
		w.syncRunID = s.Run
		if old != nil {
			if rec.JSeq == 0 || rec.JSeq != old.last+1 {
				old.complete = false
			}
			old.last = rec.JSeq
			if (old.version != 0 || s.Core.SyncTrace != 0) && (old.node != hexAddr(s.Self) || old.version != s.Core.SyncTrace) {
				w.syncErr = fmt.Errorf("sync source identity changed")
			}
			return
		}
		if s.Core.SyncTrace > journal.SyncTraceVersion {
			w.syncErr = fmt.Errorf("unsupported sync trace version")
			return
		}
		w.syncSources[s.Run] = &syncRun{node: hexAddr(s.Self), version: s.Core.SyncTrace, declaration: rec.JSeq, last: rec.JSeq, complete: rec.JSeq == 1, inputs: map[uint64]syncSource{}, handled: map[uint64]*journal.SyncRec{}}
		return
	}
	s := w.syncSources[w.syncRunID]
	b, observation := rec.Body.(*journal.SyncRec)
	if s == nil || s.version == 0 {
		if observation {
			w.syncErr = fmt.Errorf("sync control has no trace capability")
		}
		return
	}
	if rec.JSeq == 0 || rec.JSeq != s.last+1 {
		s.complete = false
	}
	s.last = rec.JSeq
	if _, gap := rec.Body.(*journal.GapRec); gap {
		s.complete = false
	}
	if !observation {
		return
	}
	if b.SequenceExhausted || b.Request == 0 {
		s.complete = false
	}
	if b.Stage == "requested" {
		s.requests++
		if b.Request == 0 {
			return
		}
		if _, exists := s.inputs[b.Request]; exists {
			w.syncErr = fmt.Errorf("duplicate sync request identity")
			return
		}
		s.inputs[b.Request] = syncSource{rec.JSeq, pos, b}
		s.maxRequest = max(s.maxRequest, b.Request)
		return
	}
	s.operations++
	if b.Operation == 0 {
		s.complete = false
		return
	}
	if _, exists := s.handled[b.Operation]; exists {
		w.syncErr = fmt.Errorf("duplicate sync processing identity")
		return
	}
	s.handled[b.Operation] = b
	s.maxOperation = max(s.maxOperation, b.Operation)
	if b.Action != "none" && !b.EventsAvailable {
		s.complete = false
	}
}

func (s *syncRun) sourceComplete() bool {
	if !s.complete || s.requests != s.maxRequest || s.operations != s.maxOperation {
		return false
	}
	for _, b := range s.handled {
		x, ok := s.inputs[b.Request]
		if !ok || x.record.Syncing != b.Syncing || x.record.Success != b.Success {
			return false
		}
	}
	return true
}

func (w *r01Writer) hasSyncEvidence() bool {
	for _, s := range w.syncSources {
		if s.version != 0 {
			return true
		}
	}
	return false
}

func (w *r01Writer) currentSync() *syncRun {
	if w.run == nil {
		return nil
	}
	s := w.syncSources[w.run.Run]
	if s == nil || s.version == 0 {
		return nil
	}
	return s
}

func (w *r01Writer) addSyncTrace(row map[string]any, seq uint64) {
	s := w.currentSync()
	if s == nil || seq != s.declaration {
		return
	}
	row["sync_trace"] = map[string]any{"version": cacheNumber(s.version), "requests": cacheNumber(s.requests), "operations": cacheNumber(s.operations), "complete": s.complete, "event_cursor": "next_sequence"}
}

// Sync context is retained outside the requested frame height range. A
// declaration has no clock; only original observations carry sampled times.
func (w *r01Writer) syncRecord(rec journal.Record, pos wal.Position) error {
	s := w.currentSync()
	if s == nil {
		return nil
	}
	r := map[string]any{"v": r01Version, "node": s.node, "run": w.run.Run, "seq": rec.JSeq, "journal_segment": pos.Segment, "journal_offset": pos.Offset}
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if rec.JSeq != s.declaration {
			return nil
		}
		if scheduler := w.scheduler[w.run.Run]; scheduler != nil && scheduler.version != 0 {
			return nil
		}
		if cache := w.currentCache(); cache != nil {
			return nil
		}
		r["type"], r["t_wall"], r["t_mono_ns"], r["clock_source"] = "sync_trace", time.Unix(0, 0).UTC().Format(time.RFC3339Nano), int64(0), "unavailable"
		w.addSyncTrace(r, rec.JSeq)
	case *journal.SyncRec:
		r["type"], r["t_wall"], r["t_mono_ns"] = "sync_control", time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano), int64(b.Mono)
		control := map[string]any{"stage": b.Stage, "request": cacheNumber(b.Request), "operation": cacheNumber(b.Operation), "syncing": b.Syncing, "success": b.Success, "first_before": b.FirstBefore, "first_after": b.FirstAfter, "running_before": b.RunningBefore, "running_after": b.RunningAfter, "action": b.Action, "failed": b.Failed, "events_available": b.EventsAvailable, "event_before": cacheNumber(b.EventBefore), "event_after": cacheNumber(b.EventAfter), "sequence_exhausted": b.SequenceExhausted}
		r["sync_control"] = control
		if b.Stage == "processed" {
			link := map[string]any{"source_available": false}
			control["request_source"] = link
			if x, ok := s.inputs[b.Request]; ok && b.Request != 0 && s.complete {
				link["source_available"], link["source_seq"], link["source_segment"], link["source_offset"] = true, cacheNumber(x.seq), cacheNumber(x.position.Segment), fmt.Sprint(x.position.Offset)
			}
		}
	default:
		return nil
	}
	return w.write(r)
}
