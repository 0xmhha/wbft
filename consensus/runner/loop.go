package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// ctlReq is a function the consensus goroutine runs for Start and Stop.
type ctlReq struct {
	f    func() error
	done chan error
}

// startGoroutines starts the consensus goroutine, the receive-check
// workers and the commit goroutine.
func (r *Runner) startGoroutines() {
	r.ctl = make(chan ctlReq)
	r.loopDone.Add(2 + r.cfg.Workers)
	go r.consensusLoop()
	go r.commitLoop()
	for i := 0; i < r.cfg.Workers; i++ {
		go r.workerLoop()
	}
}

// onLoop runs f on the consensus goroutine and waits for it.
func (r *Runner) onLoop(f func() error) error {
	req := ctlReq{f: f, done: make(chan error, 1)}
	r.ctl <- req
	return <-req.done
}

func (r *Runner) consensusLoop() {
	defer r.loopDone.Done()
	for {
		select {
		case <-r.stopLoop:
			return
		case req := <-r.ctl:
			req.done <- req.f()
			continue
		case <-r.notify:
		}
		for r.processOne() {
			select {
			case <-r.stopLoop:
				return
			case req := <-r.ctl:
				req.done <- req.f()
			default:
			}
		}
	}
}

// Pump drives a manual runner until nothing is left to do: receive checks,
// core inputs and commits. It reports whether anything was done.
func (r *Runner) Pump() bool {
	did := false
	for {
		progressed := false
		for r.inbox.checkOne(true) {
			progressed = true
		}
		for r.processOne() {
			progressed = true
		}
		if r.commitOne() {
			progressed = true
		}
		if !progressed {
			return did
		}
		did = true
	}
}

// next takes the next input: the internal queue first, then the
// application queue, then the timer queue or the peers, chosen at random
// when both have input.
func (r *Runner) next() (queued, bool) {
	if len(r.internal) > 0 {
		q := r.internal[0]
		r.internal = r.internal[1:]
		return q, true
	}
	r.appMu.Lock()
	if len(r.appQ) > 0 {
		q := r.appQ[0]
		r.appQ = r.appQ[1:]
		if _, ok := q.in.(consensus.NewHead); ok {
			q.in = consensus.NewHead{Header: r.headNote}
			r.headNote = nil
		}
		r.appMu.Unlock()
		return q, true
	}
	r.appMu.Unlock()
	hasTimer := r.timers.pending()
	hasPeer := r.inbox.hasReady()
	if hasTimer && hasPeer {
		if r.rand(2) == 0 {
			hasPeer = false
		} else {
			hasTimer = false
		}
	}
	if hasTimer {
		if t, ok := r.timers.pop(); ok {
			return queued{in: t, via: viaTimer}, true
		}
	}
	if hasPeer {
		if m, ok := r.inbox.take(); ok {
			return queued{in: m, via: viaPeer}, true
		}
	}
	return queued{}, false
}

// processOne handles one input; it reports false when there was none.
func (r *Runner) processOne() bool {
	if !r.running.Load() || r.Halted() != nil {
		return false
	}
	q, ok := r.next()
	if !ok {
		return false
	}
	r.handle(q)
	return true
}

// stepCtx carries what the output execution of one step needs.
type stepCtx struct {
	q     queued
	step  uint64
	outs  []consensus.Output
	env   []envAnswer
	seqIn types.Height
}

// handle processes one input: WAL record, core step, outputs, end-of-height
// record, journal record and snapshot.
func (r *Runner) handle(q queued) {
	r.step++
	step := r.step
	if nh, ok := q.in.(consensus.NewHead); ok {
		if nh.Header == nil {
			return
		}
		r.env.head = nh.Header
		r.lastHead.Store(nh.Header)
	}
	if t, ok := q.in.(consensus.Timeout); ok {
		stale := t.Gen != r.lastGen[t.Kind]
		r.emit(event.Record{Kind: event.TimerFire, View: event.ViewOf(t.View), Fields: map[string]any{
			"timer": t.Kind.String(), "gen": t.Gen, "stale": stale, "engine_run": r.engineRun}}, &step)
	}
	body, err := inputlog.Encode(q.in)
	if err != nil {
		r.halt(err)
		return
	}
	kind := inputlog.Kind(q.in)
	if r.d.WAL != nil {
		if _, err := r.d.WAL.Append(encodeInput(kind, body)); err != nil {
			r.halt(err)
			return
		}
	}
	before := r.core.Snapshot()
	gens := r.core.TimerGens()
	r.env.begin(true)
	outs := r.core.Step(r.env, q.in)
	answers := r.env.end()
	sc := &stepCtx{q: q, step: step, outs: outs, env: answers, seqIn: before.View.Sequence}
	r.execute(sc)
	if r.Halted() != nil {
		return
	}
	after := r.core.Snapshot()
	r.snap.Store(after)
	if _, ok := q.in.(consensus.NewHead); ok && after.Running && (!before.Running || after.View.Sequence.Cmp(before.View.Sequence) != 0) {
		r.endHeight(after, gens)
	}
	r.journalStep(sc, kind, body, after)
}

// endHeight writes the end-of-height record of the head the core left
// for, prunes the write-ahead log and releases the builder of the height.
func (r *Runner) endHeight(snap *consensus.Snapshot, gens [3]uint64) {
	h := r.env.head
	faultpoint.Hit(r.d.Faults, faultpoint.EndHeightBefore)
	if r.d.WAL != nil {
		rec, err := encodeBoundary(walEndHeight, boundaryRec{From: h.Number.AddUint64(1), Head: h, Validators: snap.Validators, Replayed: true, Gens: gens})
		if err != nil {
			r.halt(err)
			return
		}
		pos, err := r.d.WAL.AppendSync(rec)
		if err != nil {
			r.halt(err)
			return
		}
		r.boundary = append(r.boundary, pos)
		if keep := r.d.WAL.Options().KeepHeights; len(r.boundary) > keep {
			oldest := r.boundary[len(r.boundary)-keep]
			r.boundary = r.boundary[len(r.boundary)-keep:]
			if err := r.d.WAL.RemoveBefore(oldest.Segment); err != nil {
				r.log.Warn("wal prune failed", "err", err)
			}
		}
	}
	faultpoint.Hit(r.d.Faults, faultpoint.EndHeightAfter)
	if jw, ok := r.d.Journal.(interface{ NoteHead(types.Height) }); ok {
		jw.NoteHead(h.Number)
	}
	r.lastOwn = map[ownKey][]byte{}
	r.floorSkip = map[string]bool{}
}

// execute runs the outputs of one step in order.
func (r *Runner) execute(sc *stepCtx) {
	for _, o := range sc.outs {
		if r.Halted() != nil {
			return
		}
		switch o := o.(type) {
		case consensus.Broadcast:
			r.broadcast(sc, o)
		case consensus.Relay:
			if r.d.Transport != nil {
				if to := r.d.Transport.Gossip(o.Validators, uint64(o.Code), o.Payload, event.CauseRelay); len(to) > 0 {
					r.sendEvent(sc, uint64(o.Code), o.Payload, event.CauseRelay)
				}
			}
		case consensus.Schedule:
			r.internal = append(r.internal, queued{in: o.In, via: viaInternal})
		case consensus.ArmTimer:
			r.lastGen[o.Kind] = o.Gen
			r.timers.arm(o)
			f := map[string]any{"timer": o.Kind.String(), "duration_ms": o.Duration.Milliseconds(),
				"deadline_mono_ns": int64(r.d.Clock.Mono() + o.Duration), "gen": o.Gen, "engine_run": r.engineRun}
			if o.Kind == consensus.RetryTimer {
				f["target_round"] = o.Round.String()
			}
			r.emit(event.Record{Kind: event.TimerArm, View: event.ViewOf(o.View), Fields: f}, &sc.step)
		case consensus.CancelTimers:
			for _, k := range r.timers.cancel(o.Kinds) {
				r.emit(event.Record{Kind: event.TimerCancel, Fields: map[string]any{"timer": k.Kind.String(), "gen": k.Gen, "engine_run": r.engineRun}}, &sc.step)
			}
		case consensus.RequestBuild:
			if r.buildDone == nil || o.Height.Cmp(r.buildSeq) != 0 {
				if r.buildDone != nil {
					close(r.buildDone)
				}
				r.buildDone, r.buildSeq = make(chan struct{}), o.Height
			}
			wait := o.Wait(r.d.Clock.Now().UnixNano())
			r.emit(event.Record{Kind: event.BuildRequest, View: event.ViewOf(types.View{Sequence: o.Height, Round: o.Round}),
				Fields: map[string]any{"round": o.Round.String(), "wait_ms": wait.Milliseconds()}}, &sc.step)
			r.d.App.ReadyToBuild(o, wait, r.buildDone)
		case consensus.Commit:
			r.commit(sc, o)
		case consensus.Outcome:
			rec := o.Record()
			r.emit(rec, &sc.step)
			if r.d.Journal != nil {
				row := int64(o.Row)
				check := ""
				if o.Check != consensus.ClassNone {
					check = o.Check.String()
				}
				r.d.Journal.Put(journal.Record{Body: &journal.OutcomeRec{Code: uint64(o.Code), Peer: o.Peer, DedupKey: o.DedupKey,
					Outcome: o.Class(), Check: check, Row: row, Via: o.Via, Step: sc.step}})
			}
		case consensus.Event:
			r.emit(o.Record, &sc.step)
		}
	}
}

// broadcast signs, logs, sends and self-delivers an own message.
func (r *Runner) broadcast(sc *stepCtx, b consensus.Broadcast) {
	m := b.Msg
	if r.d.Signer == nil {
		r.internal = append(r.internal, queued{in: consensus.BroadcastFailed{Code: m.Code, View: m.View}, via: viaInternal})
		return
	}
	sig, err := r.d.Signer.SignVote(privval.VoteRequest{Msg: m, SealData: b.SealData, BadBlockReleased: b.BadBlockReleased})
	if err != nil {
		if !privval.IsRefusal(err) {
			r.halt(err)
			return
		}
		r.refused(sc, m, err)
		return
	}
	c := *m
	c.Seal, c.Signature = sig.Seal, sig.Signature
	payload, err := codec.EncodeMessage(&c)
	if err != nil {
		r.halt(err)
		return
	}
	if err := transport.CheckOutbound(uint64(c.Code), payload); err != nil {
		r.log.Error("own message not sendable", "code", c.Code, "err", err)
		r.internal = append(r.internal, queued{in: consensus.BroadcastFailed{Code: m.Code, View: m.View}, via: viaInternal})
		return
	}
	faultpoint.Hit(r.d.Faults, faultpoint.WALBeforeOwnMsg)
	if r.d.WAL != nil {
		if _, err := r.d.WAL.AppendSync(encodeOwn(ownRec{Code: uint64(c.Code), Payload: payload})); err != nil {
			r.halt(err)
			return
		}
	}
	faultpoint.Hit(r.d.Faults, faultpoint.WALAfterOwnMsg)
	cause := event.CauseBroadcast
	if t, ok := sc.q.in.(consensus.Timeout); ok && t.Kind == consensus.RetryTimer {
		cause = event.CauseRetry
	}
	faultpoint.Hit(r.d.Faults, faultpoint.SendBefore)
	if r.d.Transport != nil {
		r.d.Transport.Broadcast(b.Validators, uint64(c.Code), payload, cause)
	}
	faultpoint.Hit(r.d.Faults, faultpoint.SendAfter)
	r.sendEvent(sc, uint64(c.Code), payload, cause)
	r.lastOwn[ownKey{code: uint64(c.Code)}] = payload
	r.internal = append(r.internal, queued{in: consensus.Message{Code: c.Code, Payload: payload, Peer: r.cfg.Core.Self, RecvMono: r.d.Clock.Mono()}, via: viaInternal})
}

// refused reports a privval refusal to the core as BroadcastFailed.
func (r *Runner) refused(sc *stepCtx, m *codec.Message, err error) {
	if r.d.WAL != nil {
		if _, werr := r.d.WAL.Append(encodeOwn(ownRec{Code: uint64(m.Code), Refused: 1, Seq: m.View.Sequence.Big(), Round: m.View.Round.Big()})); werr != nil {
			r.halt(werr)
			return
		}
	}
	what := "privval_refusal"
	if errors.Is(err, privval.ErrBelowSignFloor) {
		what = "sign_floor_skip"
	}
	key := what + "/" + m.View.Sequence.String()
	if what == "privval_refusal" || !r.floorSkip[key] {
		r.floorSkip[key] = true
		r.emit(event.Record{Kind: event.Health, View: event.ViewOf(m.View), Fields: map[string]any{
			"what": what, "code": uint64(m.Code), "h": m.View.Sequence.String()}}, &sc.step)
	}
	r.log.Warn("privval refused a signature", "code", m.Code, "view", m.View.Sequence.String()+"/"+m.View.Round.String(), "err", err)
	r.internal = append(r.internal, queued{in: consensus.BroadcastFailed{Code: m.Code, View: m.View}, via: viaInternal})
}

func (r *Runner) sendEvent(sc *stepCtx, code uint64, payload []byte, cause event.SendCause) {
	if r.d.Events == nil {
		return
	}
	sum := sha256.Sum256(payload)
	key := codec.DedupKey(payload)
	r.emit(event.Record{Kind: event.Send, Fields: map[string]any{
		"code": code, "dedup_key": "0x" + hex.EncodeToString(key[:]), "payload_sha256": "0x" + hex.EncodeToString(sum[:]), "cause": cause}}, &sc.step)
}

// commit logs the commit request and hands the block to the commit
// goroutine.
func (r *Runner) commit(sc *stepCtx, c consensus.Commit) {
	faultpoint.Hit(r.d.Faults, faultpoint.CommitBefore)
	if r.d.WAL != nil {
		rec, err := encodeCommit(c.Block, c.Round)
		if err != nil {
			r.halt(err)
			return
		}
		if _, err := r.d.WAL.AppendSync(rec); err != nil {
			r.halt(err)
			return
		}
	}
	faultpoint.Hit(r.d.Faults, faultpoint.CommitAfter)
	prep, com := sealers(c.Block.Header)
	r.emit(event.Record{Kind: event.FinalizeHandover, Fields: map[string]any{
		"number": c.Block.Header.Number.String(), "hash": hexHash(codec.BlockHash(c.Block.Header)), "round": c.Round.String(),
		"prepared_sealers": prep, "committed_sealers": com}}, &sc.step)
	r.commitMu.Lock()
	r.commitQ = append(r.commitQ, commitJob{block: c.Block, round: c.Round, at: r.d.Clock.Mono()})
	r.commitCond.Signal()
	r.commitMu.Unlock()
}

func sealers(h *types.Header) (prepared, committed []uint32) {
	prepared, committed = []uint32{}, []uint32{}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return
	}
	if x.PreparedSeal != nil {
		prepared = x.PreparedSeal.Sealers.Sealers()
	}
	if x.CommittedSeal != nil {
		committed = x.CommittedSeal.Sealers.Sealers()
	}
	return
}

func hexHash(h types.Hash) string { return "0x" + hex.EncodeToString(h[:]) }

// commitOne runs one queued FinalizeBlock in manual mode.
func (r *Runner) commitOne() bool {
	r.commitMu.Lock()
	if len(r.commitQ) == 0 {
		r.commitMu.Unlock()
		return false
	}
	j := r.commitQ[0]
	r.commitQ = r.commitQ[1:]
	r.commitMu.Unlock()
	r.finalize(j)
	return true
}

func (r *Runner) commitLoop() {
	defer r.loopDone.Done()
	for {
		r.commitMu.Lock()
		for len(r.commitQ) == 0 {
			select {
			case <-r.stopLoop:
				r.commitMu.Unlock()
				return
			default:
			}
			r.commitCond.Wait()
		}
		j := r.commitQ[0]
		r.commitQ = r.commitQ[1:]
		r.commitMu.Unlock()
		r.finalize(j)
	}
}

// finalize calls the application and queues the result for the core.
func (r *Runner) finalize(j commitJob) {
	err := r.d.App.FinalizeBlock(j.block, j.round)
	hash := codec.BlockHash(j.block.Header)
	f := map[string]any{"number": j.block.Header.Number.String(), "hash": hexHash(hash), "ok": err == nil,
		"duration_ms": (r.d.Clock.Mono() - j.at).Milliseconds()}
	if err != nil {
		f["error_class"] = err.Error()
	}
	r.emit(event.Record{Kind: event.CommitResult, Fields: f}, nil)
	r.appMu.Lock()
	r.appQ = append(r.appQ, queued{in: consensus.CommitResult{Hash: hash, Err: err}, via: viaApp})
	r.appMu.Unlock()
	r.wake()
}

// journalStep writes the step record.
func (r *Runner) journalStep(sc *stepCtx, kind string, body []byte, after *consensus.Snapshot) {
	if r.d.Journal == nil {
		return
	}
	d, err := inputlog.OutDigest(sc.outs)
	if err != nil {
		r.log.Warn("out digest failed", "err", err)
	}
	var envs [][]byte
	for _, a := range sc.env {
		if a.call.Kind == inputlog.EnvValidatorsAt {
			continue
		}
		b, err := inputlog.EncodeEnv(a.call)
		if err == nil {
			envs = append(envs, b)
		}
	}
	rec := &journal.StepRec{EngineRun: r.engineRun, Step: sc.step, Mono: r.d.Clock.Mono(), WallNs: r.d.Clock.Now().UnixNano(),
		InputKind: kind, Input: body, Via: sc.q.via, Env: envs, ValsetDigest: consensus.ValsetDigest(after.Validators), OutDigest: d}
	if r.env.head != nil {
		rec.HeadNumber, rec.HeadHash = r.env.head.Number, codec.BlockHash(r.env.head)
	}
	r.d.Journal.Put(journal.Record{Body: rec})
}

// ownViewMessages returns the last own messages of the current view, in
// code order, for re-sending after a replay.
func (r *Runner) ownViewMessages(v types.View) []ownMsg {
	var out []ownMsg
	for k, p := range r.lastOwn { //wbft:unordered sorted below
		m, err := codec.DecodeMessage(codec.Code(k.code), p)
		if err != nil || m.View.Cmp(v) != 0 {
			continue
		}
		out = append(out, ownMsg{code: codec.Code(k.code), payload: p, msg: m})
	}
	slices.SortStableFunc(out, func(a, b ownMsg) int { return int(a.code) - int(b.code) })
	return out
}

type ownMsg struct {
	code    codec.Code
	payload []byte
	msg     *codec.Message
}
