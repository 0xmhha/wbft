package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

type schedulerRun struct {
	node                                    string
	version, declaration, operations, steps uint64
}

// Full scheduler context is retained independently of the frame height filter.
// Counts detect a truncated export; raw journal positions remain audit pointers.
func (w *r01Writer) indexScheduler(rec journal.Record) {
	if w.schedulerErr != nil {
		return
	}
	if s, ok := rec.Body.(*journal.SegmentRec); ok {
		if w.scheduler == nil {
			w.scheduler = map[string]*schedulerRun{}
		}
		if w.schedulerRun != s.Run && w.scheduler[s.Run] != nil && (w.scheduler[s.Run].version != 0 || s.Core.TimerTrace != 0) {
			w.schedulerErr = fmt.Errorf("scheduler writer run reappeared")
			return
		}
		w.schedulerRun = s.Run
		if old := w.scheduler[s.Run]; old != nil {
			if (old.version != 0 || s.Core.TimerTrace != 0) && (old.node != hexAddr(s.Self) || old.version != s.Core.TimerTrace) {
				w.schedulerErr = fmt.Errorf("scheduler source identity changed")
			}
			return
		}
		if s.Core.TimerTrace > journal.TimerTraceVersion {
			w.schedulerErr = fmt.Errorf("unsupported scheduler trace version")
			return
		}
		w.scheduler[s.Run] = &schedulerRun{node: hexAddr(s.Self), version: s.Core.TimerTrace, declaration: rec.JSeq}
		return
	}
	s := w.scheduler[w.schedulerRun]
	if s == nil || s.version == 0 {
		return
	}
	switch b := rec.Body.(type) {
	case *journal.TimerRec:
		if _, err := timerMetadata(b); err != nil {
			w.schedulerErr = err
			return
		}
		s.operations++
	case *journal.StepRec:
		s.steps++
	}
}

func (w *r01Writer) hasSchedulerEvidence() bool {
	for _, s := range w.scheduler {
		if s.version != 0 {
			return true
		}
	}
	return false
}

func (w *r01Writer) schedulerRecord(rec journal.Record, pos wal.Position) error {
	if w.run == nil {
		return nil
	}
	s := w.scheduler[w.run.Run]
	if s == nil || s.version == 0 {
		return nil
	}
	r := map[string]any{"v": r01Version, "node": s.node, "run": w.run.Run, "seq": rec.JSeq, "journal_segment": pos.Segment, "journal_offset": pos.Offset}
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if rec.JSeq != s.declaration {
			return nil
		}
		r["type"], r["t_wall"], r["t_mono_ns"], r["clock_source"] = "scheduler_trace", time.Unix(0, 0).UTC().Format(time.RFC3339Nano), int64(0), "unavailable"
		r["scheduler_trace"] = map[string]string{"version": strconv.FormatUint(s.version, 10), "operations": strconv.FormatUint(s.operations, 10), "steps": strconv.FormatUint(s.steps, 10)}
		// Both capabilities originate from the same raw segment record.
		// Keep one row and its original sequence instead of inventing a second
		// sequence or duplicating the identity consumers require to be unique.
		if cache := w.currentCache(); cache != nil && rec.JSeq == cache.declaration {
			r["cache_trace"] = cacheTraceMetadata(cache)
		}
	case *journal.TimerRec:
		op, err := timerMetadata(b)
		if err != nil {
			return err
		}
		r["type"], r["t_wall"], r["t_mono_ns"] = "timer_operation", time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano), int64(b.Mono)
		r["engine_run"], r["step"], r["timer_operation"] = b.EngineRun, b.Step, op
	case *journal.StepRec:
		if own := w.ownRun(); own != nil && own.inputs[rec.JSeq] != nil {
			return nil
		}
		r["type"], r["t_wall"], r["t_mono_ns"] = "scheduler_step", time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano), int64(b.Mono)
		r["engine_run"], r["step"], r["input_kind"], r["via"] = b.EngineRun, b.Step, b.InputKind, b.Via
		if b.Entry != nil {
			r["entry_t_mono_ns"] = strconv.FormatInt(int64(b.Entry.Mono), 10)
			r["entry_t_wall"] = time.Unix(0, b.Entry.WallNs).UTC().Format(time.RFC3339Nano)
		}
	default:
		return nil
	}
	return w.write(r)
}

func timerMetadata(b *journal.TimerRec) (map[string]any, error) {
	if !slices.Contains([]string{"core", "restore", "lifecycle", "dequeue"}, b.Source) || !slices.Contains([]string{"arm", "replace", "cancelled", "queued", "pop", "cancel", "clear"}, b.Action) {
		return nil, fmt.Errorf("unsupported scheduler operation")
	}
	if b.Action == "cancel" || b.Action == "clear" {
		if len(b.Input) != 0 || b.ArmEngineRun != 0 || b.ArmStep != 0 || b.ArmOutput != 0 || b.EntryMono != 0 || b.Deadline != 0 {
			return nil, fmt.Errorf("cancellation contains timeout identity")
		}
	} else if len(b.Input) == 0 || len(b.Kinds) != 0 {
		return nil, fmt.Errorf("scheduler timeout context is incomplete")
	}
	number := func(n uint64) string { return strconv.FormatUint(n, 10) }
	kinds := []string{}
	for _, k := range b.Kinds {
		if k > uint64(consensus.FutureTimer) {
			return nil, fmt.Errorf("invalid scheduler cancellation kind")
		}
		kinds = append(kinds, consensus.TimerKind(k).String())
	}
	r := map[string]any{"sequence": number(b.Sequence), "action": b.Action, "source": b.Source, "output": number(b.Output), "arm_engine_run": number(b.ArmEngineRun), "arm_step": number(b.ArmStep), "arm_output": number(b.ArmOutput), "arm_entry_mono_ns": strconv.FormatInt(int64(b.EntryMono), 10), "deadline_mono_ns": strconv.FormatInt(int64(b.Deadline), 10), "cancel_kinds": kinds, "decode": "not_applicable"}
	if len(b.Input) == 0 {
		return r, nil
	}
	x, err := inputlog.Decode(inputlog.KindTimeout, b.Input, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid scheduler timeout: %w", err)
	}
	tm, ok := x.(consensus.Timeout)
	if !ok || tm.Kind > consensus.FutureTimer {
		return nil, fmt.Errorf("invalid scheduler timeout kind")
	}
	sum := sha256.Sum256(b.Input)
	r["timeout_sha256"] = hex.EncodeToString(sum[:])
	r["timer"], r["generation"], r["height"], r["round"], r["decode"] = tm.Kind.String(), number(tm.Gen), tm.View.Sequence.String(), tm.View.Round.String(), "complete"
	return r, nil
}
