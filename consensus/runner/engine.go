package runner

import (
	"bytes"
	"context"
	"fmt"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// startEngine creates the core, replays the write-ahead log if enabled and
// starts the engine run. It runs on the consensus goroutine.
func (r *Runner) startEngine(_ context.Context, head *types.Header) error {
	r.engineRun++
	r.step = 0
	r.internal = nil
	r.lastOwn = map[ownKey][]byte{}
	r.floorSkip = map[string]bool{}
	r.lastGen = [3]uint64{}
	r.replay = ReplayInfo{}
	if jw, ok := r.d.Journal.(interface{ SetEngineRun(uint64) }); ok {
		jw.SetEngineRun(r.engineRun)
	}
	r.env = &liveEnv{r: r, head: head}
	from := head.Number.AddUint64(1)

	var plan *replayPlan
	if r.cfg.ReplayWAL && r.d.WAL != nil {
		p, err := r.planReplay(from)
		if err != nil {
			r.replay.Stopped = err.Error()
		} else {
			plan = p
		}
	}
	replayed := false
	var journalRecs []*journal.StepRec
	var replayTimers [3]*consensus.ArmTimer
	if plan != nil && len(plan.steps) > 0 {
		core, recs, res := r.runReplay(plan)
		if res.err != nil && res.lastPartial {
			// The last step was cut short by the crash: replay without it.
			plan.steps = plan.steps[:len(plan.steps)-1]
			core, recs, res = r.runReplay(plan)
		}
		r.replay.Records = res.fed
		if res.err != nil {
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
	if !replayed {
		r.core = consensus.NewState(r.cfg.Core)
		r.env.begin(false)
		outs := r.core.Step(r.env, consensus.Start{})
		answers := r.env.end()
		r.running.Store(true)
		r.step++
		sc := &stepCtx{q: queued{in: consensus.Start{}, via: viaEngine}, step: r.step, outs: outs, env: answers}
		body, _ := inputlog.Encode(consensus.Start{})
		r.execute(sc)
		snap := r.core.Snapshot()
		r.snap.Store(snap)
		if err := r.writeRunStart(from, head, snap, false); err != nil {
			return err
		}
		r.journalStep(sc, inputlog.KindStart, body, snap)
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
		r.snap.Store(snap)
		if err := r.writeRunStart(from, r.env.head, snap, true); err != nil {
			return err
		}
		r.afterReplay(replayTimers, snap)
	}
	r.replay.Replayed = replayed
	r.lastHead.Store(r.env.head)
	r.startHousekeeping()
	f := map[string]any{"engine_run": r.engineRun, "reason": "start", "replay": map[string]any{
		"records": r.replay.Records, "stopped": nilIfEmpty(r.replay.Stopped), "replayed": replayed}}
	r.emit(event.Record{Kind: event.EngineStart, Fields: f}, nil)
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
	rec, err := encodeBoundary(walRunStart, boundaryRec{From: from, Head: head, Validators: snap.Validators, Replayed: replayed})
	if err != nil {
		return err
	}
	pos, err := r.d.WAL.AppendSync(rec)
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
	if r.core != nil {
		r.step++
		outs := r.core.Step(r.env, consensus.Stop{})
		sc := &stepCtx{q: queued{in: consensus.Stop{}, via: viaEngine}, step: r.step, outs: outs}
		r.execute(sc)
		body, _ := inputlog.Encode(consensus.Stop{})
		snap := r.core.Snapshot()
		r.journalStep(sc, inputlog.KindStop, body, snap)
	}
	r.stopHousekeeping()
	r.timers.clear()
	r.inbox.clear()
	r.internal = nil
	r.appMu.Lock()
	r.appQ, r.headNote = nil, nil
	r.appMu.Unlock()
	if r.buildDone != nil {
		close(r.buildDone)
		r.buildDone = nil
	}
	r.running.Store(false)
	r.snap.Store(&consensus.Snapshot{})
	r.emit(event.Record{Kind: event.EngineStop, Fields: map[string]any{"engine_run": r.engineRun, "reason": reason}}, nil)
}

// replayPlan is the part of the log a replay feeds.
type replayPlan struct {
	head  *types.Header
	vs    *validator.Set
	gens  [3]uint64
	steps []walStep
}

// planReplay finds the last boundary of height from (an end-of-height
// record of from - 1, or a run start at from whose core did not continue a
// replay) and collects the input records after it that belong to height
// from. Run starts that continued a replay are skipped; the plan ends at
// the next end-of-height record, at a run start that did not continue a
// replay, or at a new head of height from or above.
func (r *Runner) planReplay(from types.Height) (*replayPlan, error) {
	fs, dir := r.d.WAL.FS()
	recs, _, err := wal.ReadAll(fs, dir)
	if err != nil {
		// Damage the open did not repair (a torn tail being written now);
		// use what was read.
		r.log.Warn("wal read stopped early", "err", err)
	}
	start := -1
	var b boundaryRec
	for i, rec := range recs {
		if rec.Format != walFormat || (rec.Kind != walEndHeight && rec.Kind != walRunStart) {
			continue
		}
		x, err := decodeBoundary(rec.Body)
		if err != nil {
			return nil, fmt.Errorf("wal boundary record: %w", err)
		}
		if x.From.Cmp(from) != 0 {
			continue
		}
		if rec.Kind == walEndHeight || !x.Replayed {
			start, b = i, x
		}
	}
	if start < 0 {
		return &replayPlan{}, nil
	}
	plan := &replayPlan{head: b.Head, vs: b.Validators, gens: b.Gens}
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
		if rec.Format != walFormat {
			continue
		}
		switch rec.Kind {
		case walRunStart:
			x, err := decodeBoundary(rec.Body)
			if err != nil || !x.Replayed || x.From.Cmp(from) != 0 {
				break loop
			}
		case walEndHeight:
			break loop
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
	return plan, nil
}

// replayResult is the outcome of feeding a plan.
type replayResult struct {
	fed         int
	err         error
	lastPartial bool // the error is at the last step and may be a torn step
	lastGen     [3]uint64
	lastOwn     map[ownKey][]byte
	timers      [3]*consensus.ArmTimer
}

// runReplay feeds a plan to a new core: a Start from the boundary, then
// every recorded input with its recorded Env answers. Outputs are not
// executed; own messages are compared with the recorded ones. It returns
// the core, the journal step records of the replay and the result.
func (r *Runner) runReplay(plan *replayPlan) (*consensus.State, []*journal.StepRec, replayResult) {
	res := replayResult{lastOwn: map[ownKey][]byte{}}
	core := consensus.NewState(r.cfg.Core)
	core.RestoreTimerGens(plan.gens)
	var recs []*journal.StepRec
	var step uint64
	senv := &startEnv{head: plan.head, vs: plan.vs}
	record := func(kind string, body []byte, via string, outs []consensus.Output, env []inputlog.EnvCall, head *types.Header) {
		step++
		d, _ := inputlog.OutDigest(outs)
		var envs [][]byte
		for _, c := range env {
			if c.Kind == inputlog.EnvValidatorsAt {
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
	record(inputlog.KindStart, startBody, viaWAL, outs, nil, plan.head)
	recs[0].TimerGens = plan.gens[:]
	env := &replayEnv{head: plan.head}
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
		record(s.kind, s.body, viaWAL, outs, env.used, plan.head)
	}
	return core, recs, res
}

// compareOwn checks the Broadcast outputs of a replayed step against the
// own-message records of the step: the same code and signing payload (the
// seal included), or the same view for a refused one.
func compareOwn(outs []consensus.Output, own []ownRec, last map[ownKey][]byte) error {
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
		want, err := codec.SigningPayload(m, false, nil)
		if err != nil {
			return err
		}
		c := *b.Msg
		c.Seal = m.Seal
		got, err := codec.SigningPayload(&c, false, nil)
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
	vars := r.core.Vars()
	for _, t := range timers {
		if t != nil {
			r.timers.arm(*t)
			r.emit(event.Record{Kind: event.TimerArm, View: event.ViewOf(t.View), Fields: map[string]any{
				"timer": t.Kind.String(), "duration_ms": t.Duration.Milliseconds(), "gen": t.Gen, "engine_run": r.engineRun, "rearmed": true}}, nil)
		}
	}
	if vars == nil {
		return
	}
	for _, m := range r.ownViewMessages(snap.View) {
		switch m.code {
		case codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange:
		default:
			continue
		}
		if r.d.Transport != nil {
			r.d.Transport.Broadcast(snap.Validators, uint64(m.code), m.payload, event.CauseReplay)
		}
		r.emit(event.Record{Kind: event.Send, Fields: map[string]any{"code": uint64(m.code), "cause": event.CauseReplay}}, nil)
		if !counted(vars, m.code, r.cfg.Core.Self) {
			r.internal = append(r.internal, queued{in: consensus.Message{Code: m.code, Payload: m.payload, Peer: r.cfg.Core.Self, RecvMono: r.d.Clock.Mono()}, via: viaInternal})
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
