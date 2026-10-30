package runner

import (
	"bytes"
	"fmt"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func (r *Runner) validatorHistoryControl(before []uint64, view validatorHistoryView, outs []consensus.Output) (validatorHistoryControl, error) {
	c := validatorHistoryControl{Version: functionalHistoryVersion(r.cfg.Core), Head: validatorHistoryHeadBytes(r.env.head),
		Before: before, After: r.core.TimerGenerations(), BeforeView: view, AfterView: validatorHistoryAdoption(r.core)}
	var err error
	c.Wait, err = validatorHistoryWaitBytes(r.core.ValidatorStartWait())
	if err != nil {
		return c, err
	}
	c.Outputs, err = inputlog.OutDigest(outs)
	return c, err
}

func (r *Runner) validatorHistoryPending(excluded uint64) []deferredRecord {
	if r.nextHeight == nil {
		return nil
	}
	p := r.nextHeight
	p.mu.Lock()
	defer p.mu.Unlock()
	var pending []deferredRecord
	for _, id := range p.order {
		e := p.entries[id]
		if id != excluded && (e.stage == deferredPending || e.stage == deferredDispatch) {
			pending = append(pending, e.record)
		}
	}
	return pending
}

func (r *Runner) prepareValidatorHistoryStep(q queued, kind string, body []byte, answers []envAnswer, outs []consensus.Output, before []uint64, view validatorHistoryView) (bool, error) {
	c, err := r.validatorHistoryControl(before, view, outs)
	if err != nil {
		return false, err
	}
	c.Mode = validatorControlIntent
	footer := c
	footer.Mode = validatorControlComplete
	footerKind := walValidatorComplete
	previous, _ := view.value()
	current, _ := c.AfterView.value()
	height := view.Adopted == 1 && c.AfterView.Adopted == 1 && current.Sequence.Cmp(previous.Sequence) > 0
	if height {
		footerKind = walEndHeight
	}
	var excluded uint64
	raw := encodeInput(kind, body)
	if q.deferred != nil {
		excluded = q.deferred.record.ID
		encoded, err := rlp.Encode(q.deferred.record)
		if err != nil {
			return false, err
		}
		raw = wal.Record{Format: nextHeightFormat, Kind: walDeferredInput, Body: encoded}
	}
	inner, err := validatorHistoryInner(r.cfg, footerKind, footer, r.core, r.validatorHistoryPending(excluded))
	if err != nil {
		return false, err
	}
	footer.InnerFormat, footer.Inner = uint64(inner.Format), inner.Body
	if err := r.validatorHistory.begin(inputRec{Kind: kind, Body: body}, raw, answers, outs, c, footer, footerKind); err != nil {
		return false, err
	}
	if err := validatorHistoryTrack(&r.validatorHistory.timers, q.in, outs); err != nil {
		return false, err
	}
	return height, nil
}

func (r *Runner) startValidatorHistory(head *types.Header) error {
	records, positions, err := r.readReplayWAL()
	if err != nil {
		return fmt.Errorf("%w: %v", errValidatorHistoryProfile, err)
	}
	var replaySteps []*journal.StepRec
	var collect func(*journal.StepRec)
	if r.d.Journal != nil {
		collect = func(step *journal.StepRec) { replaySteps = append(replaySteps, step) }
	}
	parsed, err := parseValidatorHistoryWithSteps(r.cfg, records, positions, collect)
	if err != nil {
		return err
	}
	if len(records) != 0 && (head.Number.Cmp(parsed.head.Number) < 0 || head.Number.Cmp(parsed.head.Number) == 0 && !bytes.Equal(validatorHistoryHeadBytes(head), validatorHistoryHeadBytes(parsed.head))) {
		return fmt.Errorf("%w: canonical head behind or conflicting", errValidatorHistoryProfile)
	}
	w, err := newValidatorHistoryWriter(r.cfg, records, parsed, r.appendOriginalFunctionalWAL)
	if err != nil {
		return err
	}
	r.validatorHistory, r.validatorWrite = w, w.append
	defer func() {
		if r.Halted() != nil {
			_ = w.abort(r.Halted())
		}
	}()
	r.emit(event.Record{Kind: event.EngineStart, Fields: map[string]any{"engine_run": r.engineRun, "reason": "start", "replay": map[string]any{
		"records": parsed.steps, "stopped": nil, "replayed": len(records) != 0, "enabled": true, "available": true}}}, nil)
	if len(records) == 0 {
		r.core = parsed.core
		r.step++
		step := r.step
		r.stepAt = event.Stamp{Wall: r.d.Clock.Now(), Mono: r.d.Clock.Mono(), Step: &step}
		before := r.core.Snapshot()
		pre, view := r.core.TimerGenerations(), validatorHistoryAdoption(r.core)
		r.env.begin(false)
		outs := r.core.Step(r.env, consensus.Start{})
		answers := r.env.end()
		if err := validatorHistorySeedOutputs(outs); err != nil {
			return err
		}
		c, err := r.validatorHistoryControl(pre, view, outs)
		if err != nil {
			return err
		}
		c.Mode, c.InputKind = validatorControlSeed, inputlog.KindStart
		c.Options, err = validatorHistoryOptionsBytes(r.cfg)
		if err != nil {
			return err
		}
		body, _ := inputlog.Encode(consensus.Start{})
		c.InputHash, err = validatorHistoryInputHash(inputlog.KindStart, body)
		if err != nil {
			return err
		}
		for _, answer := range answers {
			witness, err := validatorHistoryWitness(answer.call)
			if err != nil {
				return err
			}
			c.Environment = append(c.Environment, witness)
		}
		inner, err := validatorHistoryInner(r.cfg, walRunStart, c, r.core, nil)
		if err != nil {
			return err
		}
		c.InnerFormat, c.Inner = uint64(inner.Format), inner.Body
		if err := w.control(walRunStart, c); err != nil {
			return err
		}
		if err := validatorHistoryTrack(&w.timers, consensus.Start{}, outs); err != nil {
			return w.abort(err)
		}
		r.running.Store(true)
		sc := &stepCtx{q: queued{in: consensus.Start{}, via: viaEngine}, step: r.step, outs: outs, env: answers, startGens: pre}
		r.execute(sc)
		if r.Halted() != nil {
			return r.Halted()
		}
		snap := r.core.Snapshot()
		r.publishSnapshot(snap, snapshotStart)
		r.journalStep(sc, inputlog.KindStart, body, snap)
		r.observeCoreStep(sc, inputlog.KindStart, body, before, snap)
	} else {
		r.core, r.env.head = parsed.core, parsed.head
		r.lastOwn = parsed.lastOwn
		copy(r.lastGen[:], r.core.TimerGenerations())
		r.replay = ReplayInfo{Replayed: true, Records: int(parsed.steps)}
		if err := r.restoreNextHeight(parsed.pending); err != nil {
			return w.abort(err)
		}
		if r.nextHeight != nil {
			r.nextHeight.mu.Lock()
			r.nextHeight.next = max(r.nextHeight.next, parsed.lastAdmission)
			r.nextHeight.mu.Unlock()
		}
		c, err := r.validatorHistoryControl(r.core.TimerGenerations(), validatorHistoryAdoption(r.core), nil)
		if err != nil {
			return err
		}
		c.Mode, c.Outputs = validatorControlResume, types.Hash{}
		inner, err := validatorHistoryInner(r.cfg, walRunStart, c, r.core, parsed.pending)
		if err != nil {
			return err
		}
		c.InnerFormat, c.Inner = uint64(inner.Format), inner.Body
		if err := w.control(walRunStart, c); err != nil {
			return err
		}
		for index, step := range replaySteps {
			step.EngineRun, step.Step = r.engineRun, uint64(index)+1
			step.Mono, step.WallNs = r.d.Clock.Mono(), r.d.Clock.Now().UnixNano()
			r.d.Journal.Put(journal.Record{Body: step})
		}
		r.step = parsed.steps + 1
		r.running.Store(true)
		if head.Number.Cmp(parsed.head.Number) > 0 {
			r.handle(queued{in: consensus.NewHead{Header: head}, via: viaEngine})
		}
		if r.Halted() != nil {
			return r.Halted()
		}
		r.restoreValidatorHistoryOutputs()
		if r.Halted() != nil {
			return r.Halted()
		}
		r.publishSnapshot(r.core.Snapshot(), snapshotReplay)
	}
	r.lastHead.Store(r.env.head)
	if p := r.nextHeight; p != nil {
		p.mu.Lock()
		p.active = true
		p.mu.Unlock()
		r.wake()
	}
	r.startHousekeeping()
	return nil
}

func validatorHistorySameArm(a, b *consensus.ArmTimer) bool {
	return a != nil && b != nil && a.Kind == b.Kind && a.Gen == b.Gen && a.View.Cmp(b.View) == 0 && a.Round.Cmp(b.Round) == 0 && a.Digest == b.Digest
}

func (r *Runner) restoreValidatorHistoryOutputs() {
	w := r.validatorHistory
	gens := r.core.TimerGenerations()
	wait := r.core.ValidatorStartWait()
	var timers [5]*consensus.ArmTimer
	for kind, timer := range w.timers {
		if timer == nil || kind >= len(gens) || timer.Gen != gens[kind] || validatorHistorySameArm(timer, w.installed[kind]) {
			continue
		}
		if wait != nil && (kind != int(consensus.ValidatorStartTimer) || !wait.Live || timer.Gen != wait.Generation || timer.View.Sequence.Cmp(wait.Target) != 0 || timer.Round.Cmp(wait.RequestedRound) != 0) {
			continue
		}
		if wait == nil && kind == int(consensus.ValidatorStartTimer) {
			continue
		}
		timers[kind] = timer
	}
	r.afterReplayTimers(timers[:], r.core.Snapshot())
	if r.Halted() != nil || wait != nil || r.buildDone != nil {
		return
	}
	if build := r.core.RestoreBuildRequest(); build != nil {
		sc := &stepCtx{step: r.step, outs: []consensus.Output{*build}}
		r.execute(sc)
	}
}
