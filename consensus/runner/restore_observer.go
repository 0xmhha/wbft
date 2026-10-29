package runner

import (
	"bytes"
	"slices"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// RestoreSourceObserver is an optional extension of WALReadSourceObserver. Its
// detached terminal record is published before the next actual live step.
type RestoreSourceObserver interface{ ObserveRestore(journal.RestoreRec) }

func (r *Runner) beginRestoreSource(from types.Height) {
	r.restoreSource = nil
	r.restoreSourceBytes = 0
	if _, ok := r.d.WALReadSources.(RestoreSourceObserver); !ok {
		return
	}
	r.restoreSource = &journal.RestoreRec{Version: journal.RestoreSourceVersion, EngineRun: r.engineRun, From: from.String()}
	if !r.cfg.ReplayWAL {
		r.restoreSource.Unavailable = "replay_disabled"
	} else if r.d.WAL == nil {
		r.restoreSource.Unavailable = "wal_missing"
	} else if r.cfg.Core.Improvements.Has(consensus.DeferValidatorStart) {
		r.restoreSource.Unavailable = "validator_start_profile"
	} else if r.nextHeight != nil {
		r.restoreSource.Unavailable = "next_height"
	}
}
func (r *Runner) observeRestorePlan(p *replayPlan, err error) {
	s := r.restoreSource
	if s == nil {
		return
	}
	if err != nil {
		s.PlanFailed = 1
		return
	}
	if p == nil {
		return
	}
	if p.boundary >= 0 {
		s.Boundary = uint64(p.boundary) + 1
	}
	if uint64(len(p.steps)) > r.d.WALReadSourceLimits.Frames {
		s.Unavailable = "frame_limit"
		return
	}
	if !r.chargeRestoreSource(uint64(len(p.steps)) * 8) {
		return
	}
	for _, in := range p.steps {
		s.Inputs = append(s.Inputs, uint64(in.index)+1)
	}
}
func (r *Runner) runReplayObserved(p *replayPlan) (*consensus.State, []*journal.StepRec, replayResult) {
	core, recs, res := r.runReplay(p)
	s := r.restoreSource
	if s == nil || s.Unavailable != "" {
		return core, recs, res
	}
	width := r.restoreTimerWidth()
	a := journal.RestoreAttempt{Inputs: uint64(len(p.steps)), Fed: uint64(res.fed), Steps: uint64(len(recs)), Generations: append([]uint64(nil), res.lastGen[:width]...), Timers: make([][]byte, width)}
	if res.err != nil {
		a.Failed = 1
	}
	if res.lastPartial {
		a.LastPartial = 1
	}
	var err error
	a.Snapshot, err = journal.RestoreSnapshotDigest(core.Snapshot())
	if err != nil {
		s.Unavailable = "snapshot_encoding"
	}
	for k, payload := range res.lastOwn {
		if !r.chargeRestoreSource(uint64(len(payload))) {
			return core, recs, res
		}
		a.Own = append(a.Own, journal.RestoreOwn{Code: k.code, Payload: bytes.Clone(payload)})
	}
	slices.SortFunc(a.Own, func(a, b journal.RestoreOwn) int {
		if a.Code < b.Code {
			return -1
		}
		if a.Code > b.Code {
			return 1
		}
		return 0
	})
	for i, t := range res.timers[:width] {
		if t != nil {
			a.Timers[i], err = inputlog.EncodeOutputs([]consensus.Output{*t})
			if err != nil {
				s.Unavailable = "output_encoding"
			}
			if !r.chargeRestoreSource(uint64(len(a.Timers[i]))) {
				return core, recs, res
			}
		}
	}
	s.Attempts = append(s.Attempts, a)
	return core, recs, res
}
func (r *Runner) finishRestoreSource(startErr *error) {
	s := r.restoreSource
	if s == nil {
		return
	}
	r.restoreSource = nil
	if *startErr == nil {
		s.Installed = 1
	}
	if r.replay.Replayed {
		s.Replayed = 1
	}
	s.Steps = r.step
	if r.core != nil {
		var err error
		s.Snapshot, err = journal.RestoreSnapshotDigest(r.core.Snapshot())
		if err != nil {
			s.Unavailable = "snapshot_encoding"
		}
	}
	if s.Read.Log == 0 && s.Unavailable == "" {
		s.Unavailable = "read_source_missing"
	}
	s.Generations = append([]uint64(nil), r.lastGen[:r.restoreTimerWidth()]...)
	if s.Unavailable == "" {
		for key, payload := range r.lastOwn {
			if !r.chargeRestoreValue(s, uint64(len(payload))) {
				break
			}
			s.Own = append(s.Own, journal.RestoreOwn{Code: key.code, Payload: bytes.Clone(payload)})
		}
		slices.SortFunc(s.Own, func(a, b journal.RestoreOwn) int {
			if a.Code < b.Code {
				return -1
			}
			if a.Code > b.Code {
				return 1
			}
			return 0
		})
	}
	if s.Unavailable != "" {
		s.Inputs = nil
		s.Attempts = nil
		s.Generations = nil
		s.Own = nil
	}
	s.Mono, s.WallNs = uint64(r.d.Clock.Mono()), uint64(r.d.Clock.Now().UnixNano())
	r.d.WALReadSources.(RestoreSourceObserver).ObserveRestore(*s)
}

// These limits bound retained diagnostic indexes and payload spans, not the
// original read, core execution, hashing allocations or process heap.
func (r *Runner) chargeRestoreSource(n uint64) bool { return r.chargeRestoreValue(r.restoreSource, n) }
func (r *Runner) chargeRestoreValue(s *journal.RestoreRec, n uint64) bool {
	if s == nil || s.Unavailable != "" {
		return false
	}
	limit := r.d.WALReadSourceLimits.Bytes
	if limit == 0 {
		s.Unavailable = "inspection_limits_required"
		return false
	}
	if n > limit-r.restoreSourceBytes {
		s.Unavailable = "byte_limit"
		return false
	}
	r.restoreSourceBytes += n
	return true
}
