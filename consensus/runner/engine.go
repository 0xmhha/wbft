package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// startEngine creates the core, replays the write-ahead log if enabled and
// starts the engine run. It runs on the consensus goroutine.
func (r *Runner) startEngine(_ context.Context, head *types.Header) (startErr error) {
	r.engineRun++
	r.beginRestoreSource(head.Number.AddUint64(1))
	defer r.finishRestoreSource(&startErr)
	r.manualChecks = 0
	r.manualStepPending = false
	r.step = 0
	r.clearInternal("reset")
	r.lastOwn = map[ownKey][]byte{}
	r.floorSkip = map[string]bool{}
	r.lastGen = [5]uint64{}
	r.replay = ReplayInfo{}
	if jw, ok := r.d.Journal.(interface{ SetEngineRun(uint64) }); ok {
		jw.SetEngineRun(r.engineRun)
	}
	r.env = &liveEnv{r: r, head: head}
	from := head.Number.AddUint64(1)
	r.validatorHistory, r.validatorWrite = nil, nil
	if functionalHistorySelected(r.cfg.Core) && r.d.WAL != nil {
		return r.startValidatorHistory(head)
	}
	if r.d.WAL != nil {
		fs, dir := r.d.WAL.FS()
		records, _, _ := wal.ReadAll(fs, dir)
		for _, record := range records {
			if record.Format == validatorStartFormat || record.Format == roundChangeDomainFormat {
				return errValidatorHistoryProfile
			}
		}
	}

	// Disabling replay must not silently discard an opt-in WAL profile.
	if !r.cfg.ReplayWAL && r.d.WAL != nil {
		fs, dir := r.d.WAL.FS()
		records, _, _ := wal.ReadAll(fs, dir)
		for _, rec := range records {
			if rec.Format == roundChangeRetryFormat {
				return errRoundChangeRetryWAL
			}
			if rec.Format == priorHeadFormat {
				return errPriorHeadWAL
			}
			if rec.Format == nextHeightFormat {
				return errNextHeightWAL
			}
		}
	}
	var plan *replayPlan
	if r.cfg.ReplayWAL && r.d.WAL != nil {
		p, err := r.planReplay(from)
		r.observeRestorePlan(p, err)
		if err != nil {
			if r.cfg.Core.RoundChangeRetry != nil || r.nextHeight != nil || r.cfg.Core.Improvements.Has(consensus.BindPriorHead) || errors.Is(err, errPriorHeadWAL) || errors.Is(err, errNextHeightWAL) || errors.Is(err, errRoundChangeRetryWAL) {
				return err
			}
			r.replay.Stopped = err.Error()
		} else {
			plan = p
		}
	}
	replayed := false
	var journalRecs []*journal.StepRec
	var replayTimers [5]*consensus.ArmTimer
	if plan != nil && len(plan.steps) > 0 {
		core, recs, res := r.runReplayObserved(plan)
		if res.err != nil && res.lastPartial && r.cfg.Core.RoundChangeRetry == nil && r.nextHeight == nil && !r.cfg.Core.Improvements.Has(consensus.BindPriorHead) {
			// The last step was cut short by the crash: replay without it.
			plan.steps = plan.steps[:len(plan.steps)-1]
			core, recs, res = r.runReplayObserved(plan)
		}
		r.replay.Records = res.fed
		if res.err != nil {
			if r.cfg.Core.RoundChangeRetry != nil || r.nextHeight != nil || r.cfg.Core.Improvements.Has(consensus.BindPriorHead) {
				return res.err
			}
			r.replay.Stopped = res.err.Error()
			r.log.Warn("wal replay stopped; starting a new core", "err", res.err)
		} else {
			replayed = true
			r.core = core
			journalRecs = recs
			r.lastGen = res.lastGen
			r.lastOwn = res.lastOwn
			replayTimers = res.timers
			r.env.head = plan.head
		}
	}
	if plan != nil {
		if err := r.restoreNextHeight(plan.pending); err != nil {
			return err
		}
	}
	r.replay.Replayed = replayed
	// ENGINE_START comes before the records of the run's first step, which
	// belong to the new run.
	f := map[string]any{"engine_run": r.engineRun, "reason": "start", "replay": map[string]any{
		"records": r.replay.Records, "stopped": nilIfEmpty(r.replay.Stopped), "replayed": replayed,
		"enabled": r.cfg.ReplayWAL, "available": r.d.WAL != nil}}
	r.emit(event.Record{Kind: event.EngineStart, Fields: f}, nil)
	if !replayed {
		r.core = consensus.NewState(r.cfg.Core)
		r.step++
		step := r.step
		// The start step has its own moment, as every step (handle): its
		// records and the timers it arms are measured from it, not from
		// the last step of the previous run.
		r.stepAt = event.Stamp{Wall: r.d.Clock.Now(), Mono: r.d.Clock.Mono(), Step: &step}
		r.env.begin(false)
		var before *consensus.Snapshot
		var receiveBefore uint64
		if r.d.CoreSteps != nil {
			before = r.core.Snapshot()
			receiveBefore = r.currentReceiveScopeObservation()
		}
		var startGens []uint64
		if functionalHistorySelected(r.cfg.Core) {
			startGens = r.core.TimerGenerations()
		}
		outs := r.core.Step(r.env, consensus.Start{})
		answers := r.env.end()
		r.running.Store(true)
		sc := &stepCtx{q: queued{in: consensus.Start{}, via: viaEngine}, step: r.step, outs: outs, env: answers, startGens: startGens}
		if r.d.CoreSteps != nil {
			sc.receiveBefore, sc.receiveAfter = receiveBefore, r.currentReceiveScopeObservation()
		}
		body, _ := inputlog.Encode(consensus.Start{})
		r.execute(sc)
		snap := r.core.Snapshot()
		r.publishSnapshot(snap, snapshotStart)
		if err := r.writeRunStart(from, head, snap, false); err != nil {
			return err
		}
		r.journalStep(sc, inputlog.KindStart, body, snap)
		r.observeCoreStep(sc, inputlog.KindStart, body, before, snap)
	} else {
		r.running.Store(true)
		if r.d.Journal != nil {
			for _, rec := range journalRecs {
				rec.EngineRun = r.engineRun
				r.d.Journal.Put(journal.Record{Body: rec})
			}
		}
		r.step = uint64(len(journalRecs))
		snap := r.core.Snapshot()
		r.publishSnapshot(snap, snapshotReplay)
		if err := r.writeRunStart(from, r.env.head, snap, true); err != nil {
			return err
		}
		r.afterReplayTimers(replayTimers[:], snap)
		if r.cfg.Core.RoundChangeRetry != nil && r.Halted() != nil {
			return r.Halted()
		}
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

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (r *Runner) writeRunStart(from types.Height, head *types.Header, snap *consensus.Snapshot, replayed bool) error {
	if r.d.WAL == nil {
		return nil
	}
	rec, err := r.encodeRunnerBoundary(walRunStart, boundaryRec{From: from, Head: head, Validators: snap.Validators, PriorSource: snap.PriorSource, Replayed: replayed, LocalTimer: r.cfg.Core.Improvements.Has(consensus.ValidateRoundProposals)})
	if err != nil {
		return err
	}
	pos, err := r.appendFunctionalWAL(rec, true)
	if err != nil {
		r.halt(err)
		return err
	}
	r.boundary = append(r.boundary, pos)
	return nil
}

// stopEngine discards the core state, the armed timers and the queued
// inputs.
func (r *Runner) stopEngine(reason string) {
	var receiveBefore uint64
	if r.d.CoreSteps != nil {
		receiveBefore = r.currentReceiveScopeObservation()
	}
	r.updateReceiveContext(nil)
	if r.receiveFailures != nil {
		r.receiveFailures.Invalidate()
	}
	if r.nextHeight != nil {
		r.nextHeight.clear()
	}
	if r.core != nil {
		r.step++
		step := r.step
		r.stepAt = event.Stamp{Wall: r.d.Clock.Now(), Mono: r.d.Clock.Mono(), Step: &step}
		var before *consensus.Snapshot
		var envStart int
		if r.d.CoreSteps != nil {
			before = r.core.Snapshot()
			envStart = len(r.env.answers)
		}
		outs := r.core.Step(r.env, consensus.Stop{})
		sc := &stepCtx{q: queued{in: consensus.Stop{}, via: viaEngine}, step: r.step, outs: outs}
		r.execute(sc)
		body, _ := inputlog.Encode(consensus.Stop{})
		snap := r.core.Snapshot()
		r.journalStep(sc, inputlog.KindStop, body, snap)
		if r.d.CoreSteps != nil {
			source := *sc
			source.receiveBefore, source.receiveAfter = receiveBefore, r.currentReceiveScopeObservation()
			source.env = r.env.answers[envStart:]
			r.observeCoreStep(&source, inputlog.KindStop, body, before, snap)
		}
	}
	r.stopHousekeeping()
	r.timers.setOwner(r.engineRun, r.step, 0, "lifecycle")
	r.timers.clear()
	r.inbox.clear()
	r.clearInternal("clear")
	r.appMu.Lock()
	appBefore := len(r.appQ)
	r.appQ, r.headNote = nil, nil
	appObservation := r.appQueueRecordLocked("clear", 0, nil, r.engineRun, r.step, appBefore)
	r.appMu.Unlock()
	r.publishAppQueue(appObservation)
	if r.buildDone != nil {
		close(r.buildDone)
		r.buildDone = nil
	}
	r.running.Store(false)
	r.publishSnapshot(&consensus.Snapshot{}, snapshotStopped)
	r.emit(event.Record{Kind: event.EngineStop, Fields: map[string]any{"engine_run": r.engineRun, "reason": reason}}, nil)
}

// replayPlan is the part of the log a replay feeds.
type replayPlan struct {
	boundary    int // original record index; -1 when no eligible boundary
	pending     []deferredRecord
	head        *types.Header
	vs          *validator.Set
	priorSource *consensus.PriorHeadSource
	gens        []uint64
	steps       []walStep
}

// planReplay finds the last boundary of height from (an end-of-height
// record of from - 1, or a run start at from whose core did not continue a
// replay) and collects the input records after it that belong to height
// from. Run starts that continued a replay are skipped; the plan ends at
// the next end-of-height record, at a run start that did not continue a
// replay, or at a new head of height from or above.
func (r *Runner) planReplay(from types.Height) (*replayPlan, error) {
	recs, _, err := r.readReplayWAL()
	if err != nil {
		if r.cfg.Core.RoundChangeRetry != nil {
			return nil, fmt.Errorf("%w: %v", errRoundChangeRetryWAL, err)
		}
		// Damage the open did not repair (a torn tail being written now);
		// use what was read.
		r.log.Warn("wal read stopped early", "err", err)
	}
	start := -1
	var b boundaryRec
	for i, rec := range recs {
		if r.cfg.Core.RoundChangeRetry != nil && (rec.Kind == walRunStart || rec.Kind == walEndHeight) && rec.Format != walFormat && rec.Format != nextHeightFormat && rec.Format != priorHeadFormat && rec.Format != roundChangeRetryFormat {
			return nil, errRoundChangeRetryWAL
		}
		if rec.Format == roundChangeRetryFormat && rec.Kind != walRunStart && rec.Kind != walEndHeight {
			return nil, errRoundChangeRetryWAL
		}
		if rec.Format == priorHeadFormat && !r.cfg.Core.Improvements.Has(consensus.BindPriorHead) {
			return nil, errPriorHeadWAL
		}
		if rec.Format == nextHeightFormat && r.nextHeight == nil {
			return nil, errNextHeightWAL
		}
		if (rec.Format != walFormat && rec.Format != nextHeightFormat && rec.Format != priorHeadFormat && rec.Format != roundChangeRetryFormat) || (rec.Kind != walEndHeight && rec.Kind != walRunStart) {
			continue
		}
		x, cp, err := decodeRunnerBoundary(rec)
		if err != nil {
			if rec.Format == roundChangeRetryFormat {
				return nil, fmt.Errorf("%w: %v", errRoundChangeRetryWAL, err)
			}
			return nil, fmt.Errorf("wal boundary record: %w", err)
		}
		if err := r.checkRetryBoundary(rec, x, cp); err != nil {
			return nil, err
		}
		if cp != nil && (r.nextHeight == nil || cp.Limits != r.nextHeight.limits) {
			return nil, errors.New("runner: next-height checkpoint limits differ")
		}
		if x.From.Cmp(from) != 0 {
			continue
		}
		if rec.Kind == walEndHeight || !x.Replayed {
			start, b = i, x
		}
	}
	pending, err := r.pendingFromWAL(recs)
	if err != nil {
		return nil, err
	}
	if start < 0 {
		return &replayPlan{pending: pending, boundary: -1}, nil
	}
	if r.cfg.Core.Improvements.Has(consensus.BindPriorHead) && b.PriorSource == nil {
		return nil, errPriorHeadWAL
	}
	plan := &replayPlan{boundary: start, head: b.Head, vs: b.Validators, priorSource: b.PriorSource, gens: b.timerGenerations()}
	var cur *walStep
	flush := func() {
		if cur != nil {
			plan.steps = append(plan.steps, *cur)
			cur = nil
		}
	}
loop:
	for i := start + 1; i < len(recs); i++ {
		rec := recs[i]
		if rec.Format != walFormat && rec.Format != nextHeightFormat && rec.Format != priorHeadFormat && rec.Format != roundChangeRetryFormat {
			continue
		}
		switch rec.Kind {
		case walRunStart:
			x, _, err := decodeRunnerBoundary(rec)
			if err != nil || !x.Replayed || x.From.Cmp(from) != 0 {
				break loop
			}
		case walEndHeight:
			break loop
		case walDeferredAdmit, walDeferredDrop, walDeferredInput:
			if rec.Format != nextHeightFormat {
				return nil, errors.New("runner: deferred record has the wrong format")
			}
			var d deferredRecord
			if err := rlp.DecodeStrict(rec.Body, &d); err != nil {
				return nil, err
			}
			if rec.Kind != walDeferredInput {
				continue
			}
			flush()
			in, err := deferredInput(d)
			if err != nil {
				return nil, err
			}
			cur = &walStep{kind: in.Kind, body: in.Body, index: i, deferred: &d}
		case walInput:
			flush()
			var in inputRec
			if err := rlp.DecodeStrict(rec.Body, &in); err != nil {
				return nil, fmt.Errorf("wal input record: %w", err)
			}
			if in.Kind == inputlog.KindNewHead {
				nh, err := inputlog.Decode(in.Kind, in.Body, nil)
				if err == nil {
					if h := nh.(consensus.NewHead).Header; h != nil && h.Number.Cmp(from) >= 0 {
						break loop
					}
				}
			}
			cur = &walStep{kind: in.Kind, body: in.Body, index: i}
		case walEnv:
			if cur != nil {
				cur.env = append(cur.env, rec.Body)
			}
		case walOwnMsg:
			if cur != nil {
				var o ownRec
				if err := rlp.DecodeStrict(rec.Body, &o); err != nil {
					return nil, fmt.Errorf("wal own message record: %w", err)
				}
				cur.own = append(cur.own, o)
			}
		}
	}
	flush()
	plan.pending = pending
	return plan, nil
}

// replayResult is the outcome of feeding a plan.
type replayResult struct {
	fed         int
	err         error
	lastPartial bool // the error is at the last step and may be a torn step
	lastGen     [5]uint64
	lastOwn     map[ownKey][]byte
	timers      [5]*consensus.ArmTimer
}

// runReplay feeds a plan to a new core: a Start from the boundary, then
// every recorded input with its recorded Env answers. Outputs are not
// executed; own messages are compared with the recorded ones. It returns
// the core, the journal step records of the replay and the result.
func (r *Runner) runReplay(plan *replayPlan) (*consensus.State, []*journal.StepRec, replayResult) {
	res := replayResult{lastOwn: map[ownKey][]byte{}}
	core := consensus.NewState(r.cfg.Core)
	if err := core.RestoreTimerGenerations(plan.gens); err != nil {
		res.err = err
		return core, nil, res
	}
	var recs []*journal.StepRec
	var step uint64
	senv := &startEnv{head: plan.head, vs: plan.vs, prior: plan.priorSource, strict: r.cfg.Core.Improvements.Has(consensus.BindPriorHead)}
	record := func(kind string, body []byte, via string, outs []consensus.Output, env []inputlog.EnvCall, head *types.Header) {
		step++
		d, _ := inputlog.OutDigest(outs)
		var envs [][]byte
		for _, c := range env {
			if c.Kind == inputlog.EnvValidatorsAt && !r.cfg.Core.Improvements.Has(consensus.BindPriorHead) && !functionalHistorySelected(r.cfg.Core) {
				continue
			}
			if b, err := inputlog.EncodeEnv(c); err == nil {
				envs = append(envs, b)
			}
		}
		recs = append(recs, &journal.StepRec{Step: step, Mono: r.d.Clock.Mono(), WallNs: r.d.Clock.Now().UnixNano(),
			InputKind: kind, Input: body, Via: via, HeadNumber: head.Number, HeadHash: codec.BlockHash(head), Env: envs,
			ValsetDigest: consensus.ValsetDigest(core.Snapshot().Validators), OutDigest: d})
	}
	track := func(outs []consensus.Output) {
		for _, o := range outs {
			switch o := o.(type) {
			case consensus.ArmTimer:
				a := o
				res.timers[o.Kind] = &a
				res.lastGen[o.Kind] = o.Gen
			case consensus.CancelTimers:
				for _, k := range o.Kinds {
					res.timers[k] = nil
				}
			}
		}
	}
	startBody, _ := inputlog.Encode(consensus.Start{})
	outs := core.Step(senv, consensus.Start{})
	track(outs)
	record(inputlog.KindStart, startBody, viaWAL, outs, senv.calls, plan.head)
	recs[0].TimerGens = append([]uint64(nil), plan.gens...)
	env := &replayEnv{head: plan.head, strict: r.cfg.Core.Improvements.Has(consensus.BindPriorHead)}
	for i, s := range plan.steps {
		in, err := inputlog.Decode(s.kind, s.body, nil)
		if err != nil {
			res.err = err
			return core, recs, res
		}
		env.answers, env.used, env.err = nil, nil, nil
		for _, b := range s.env {
			c, err := inputlog.DecodeEnv(b)
			if err != nil {
				res.err = err
				return core, recs, res
			}
			env.answers = append(env.answers, c)
		}
		outs := core.Step(env, in)
		res.fed++
		if env.err != nil {
			res.err = fmt.Errorf("step %d (%s): %w", i, s.kind, env.err)
			res.lastPartial = i == len(plan.steps)-1
			return core, recs, res
		}
		if len(env.answers) > 0 {
			res.err = fmt.Errorf("step %d (%s): %d recorded Env answers left over", i, s.kind, len(env.answers))
			return core, recs, res
		}
		if err := compareOwn(outs, s.own, res.lastOwn); err != nil {
			res.err = fmt.Errorf("step %d (%s): %w", i, s.kind, err)
			res.lastPartial = i == len(plan.steps)-1
			return core, recs, res
		}
		track(outs)
		kind, body := s.kind, s.body
		if s.deferred != nil {
			d := s.deferred
			body, err = inputlog.EncodeDeferredMessage(d.message(), inputlog.CaptureOrigin{Run: d.CaptureRun, Capture: d.Capture})
			if err != nil {
				res.err = err
				return core, recs, res
			}
			kind = inputlog.KindDeferredMessage
		}
		record(kind, body, viaWAL, outs, env.used, plan.head)
	}
	return core, recs, res
}

// compareOwn checks the Broadcast outputs of a replayed step against the
// own-message records of the step: the same code and signing payload (the
// seal included), or the same view for a refused one.
func compareOwn(outs []consensus.Output, own []ownRec, last map[ownKey][]byte) error {
	return compareOwnWithDomain(outs, own, last, nil, types.Address{})
}

func compareOwnWithDomain(outs []consensus.Output, own []ownRec, last map[ownKey][]byte, domain *types.RoundChangeDomain, self types.Address) error {
	i := 0
	for _, o := range outs {
		b, ok := o.(consensus.Broadcast)
		if !ok {
			continue
		}
		if i >= len(own) {
			return fmt.Errorf("replay sent an own message (code %d) the log does not hold", b.Msg.Code)
		}
		rec := own[i]
		i++
		if rec.Code != uint64(b.Msg.Code) {
			return fmt.Errorf("replay sent code %d, the log holds code %d", b.Msg.Code, rec.Code)
		}
		if rec.Refused == 1 {
			if b.Msg.View.Sequence.Big().Cmp(rec.Seq) != 0 || b.Msg.View.Round.Big().Cmp(rec.Round) != 0 {
				return fmt.Errorf("replay sent code %d at another view than the refused one", b.Msg.Code)
			}
			continue
		}
		m, err := codec.DecodeMessage(codec.Code(rec.Code), rec.Payload)
		if err != nil {
			return err
		}
		want, err := codec.SigningPayloadWithDomain(m, domain)
		if err != nil {
			return err
		}
		if domain != nil && ecdsa.CheckSigner(want, m.Signature, self) != nil {
			return fmt.Errorf("replay own-message signature does not match its domain and owner")
		}
		c := *b.Msg
		c.Seal = m.Seal
		got, err := codec.SigningPayloadWithDomain(&c, domain)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("replay produced another own message (code %d)", b.Msg.Code)
		}
		last[ownKey{code: rec.Code}] = rec.Payload
	}
	if i != len(own) {
		return fmt.Errorf("the log holds %d own messages the replay did not send", len(own)-i)
	}
	return nil
}

// afterReplay re-arms the timers that were live at the end of the replay
// with their full durations, and sends the last own PREPARE, COMMIT and
// ROUND-CHANGE of the current view again; one the core has not counted yet
// is also delivered to the core.
func (r *Runner) afterReplay(timers [3]*consensus.ArmTimer, snap *consensus.Snapshot) {
	r.afterReplayTimers(timers[:], snap)
}

func (r *Runner) afterReplayTimers(timers []*consensus.ArmTimer, snap *consensus.Snapshot) {
	vars := r.core.Vars()
	for _, t := range timers {
		if t != nil {
			r.timers.setOwner(r.engineRun, 0, 0, "restore")
			// Keep the logical deadline separate from the later event-writing
			// moment, just as for timers armed by a core step.
			from := r.d.Clock.Mono()
			if !r.armTimer(*t, from) {
				return
			}
			fields := map[string]any{
				"timer": t.Kind.String(), "duration_ms": t.Duration.Milliseconds(),
				"deadline_mono_ns": int64(from + t.Duration),
				"gen":              t.Gen, "engine_run": r.engineRun, "rearmed": true,
			}
			if t.Kind == consensus.RetryTimer {
				fields["target_round"] = t.Round.String()
			}
			r.emit(event.Record{Kind: event.TimerArm, View: event.ViewOf(t.View), Fields: fields}, nil)
		}
	}
	if vars == nil {
		return
	}
	for _, m := range r.ownViewMessages(snap.View) {
		if r.validatorHistory != nil && bytes.Equal(r.validatorHistory.sent[ownKey{code: uint64(m.code)}], m.payload) {
			continue
		}
		switch m.code {
		case codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange:
		default:
			continue
		}
		if r.d.Transport != nil {
			r.d.Transport.Broadcast(snap.Validators, uint64(m.code), m.payload, event.CauseReplay)
		}
		r.emit(sendRecord(uint64(m.code), m.payload, event.CauseReplay, &m.msg.View), nil)
		if !counted(vars, m.code, r.cfg.Core.Self) {
			r.appendInternal(consensus.Message{Code: m.code, Payload: m.payload, Peer: r.cfg.Core.Self, RecvMono: r.d.Clock.Mono()}, "replay", 0)
		}
	}
}

// counted reports whether the core holds the node's own vote of code.
func counted(v *consensus.Vars, code codec.Code, self types.Address) bool {
	has := func(as []types.Address) bool {
		for _, a := range as {
			if a == self {
				return true
			}
		}
		return false
	}
	switch code {
	case codec.CodePrepare:
		return has(v.Prepares)
	case codec.CodeCommit:
		return has(v.Commits)
	case codec.CodeRoundChange:
		for _, rc := range v.RoundChanges {
			if has(rc.Sources) {
				return true
			}
		}
	}
	return false
}
