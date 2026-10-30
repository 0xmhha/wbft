package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"

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
	if r.nextHeight != nil {
		r.loopDone.Add(1)
		go r.nextHeightWorker()
	}
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
	if r.d.ManualProcessing != nil {
		return r.pumpProcessing()
	}
	did := false
	for {
		if r.manualCommitPending.Load() {
			return did
		}
		progressed := false
		for r.checkNextHeight() {
			progressed = true
		}
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
	selection := r.newSelection()
	r.selectionProbe(selection, "internal", len(r.internal) > 0, r.internalSourceSequence)
	if len(r.internal) > 0 {
		before := len(r.internal)
		q := r.internal[0]
		r.internal = r.internal[1:]
		observation := r.internalRecord("pop", q, "", 0, before)
		var source uint64
		if observation != nil {
			source = observation.Sequence
		}
		r.publishInternal(observation)
		return r.finishSelection(selection, "internal", source, q, true)
	}
	r.appMu.Lock()
	r.selectionProbe(selection, "app", len(r.appQ) > 0, r.appSourceSequence)
	if len(r.appQ) > 0 {
		before := len(r.appQ)
		q := r.appQ[0]
		r.appQ = r.appQ[1:]
		if _, ok := q.in.(consensus.NewHead); ok {
			q.in = consensus.NewHead{Header: r.headNote}
			r.headNote = nil
		}
		observation := r.appQueueRecordLocked("pop", q.appSource, q.in, r.engineRun, r.step+1, before)
		var source uint64
		if observation != nil {
			source = observation.Sequence
		}
		r.appMu.Unlock()
		r.publishAppQueue(observation)
		return r.finishSelection(selection, "app", source, q, true)
	}
	r.appMu.Unlock()
	if selection != nil {
		selection.NextHeight = "disabled"
		if r.nextHeight != nil {
			selection.NextHeight, selection.Unavailable = "unsupported", "next_height_source"
		}
	}
	if q, ok := r.takeNextHeight(); ok {
		return r.finishSelection(selection, "next_height", 0, q, true)
	}
	hasTimer, timerProbe := r.timers.pendingSource(selection != nil)
	hasPeer, inboxProbe := r.inbox.readySource(selection != nil)
	if selection != nil {
		selection.Timer, selection.Inbox = timerProbe, inboxProbe
		if (r.d.TimerSources == nil || r.d.InboxSources == nil) && selection.Unavailable == "" {
			selection.Unavailable = "lane_source_missing"
		}
	}
	if hasTimer && hasPeer {
		choice := r.rand(2)
		if selection != nil {
			selection.Random, selection.Choice = 1, uint64(choice)
		}
		if choice == 0 {
			hasPeer = false
		} else {
			hasTimer = false
		}
	}
	if hasTimer {
		r.timers.setOwner(r.engineRun, r.step+1, 0, "dequeue")
		if t, source, ok := r.timers.popSource(); ok {
			return r.finishSelection(selection, "timer", source, queued{in: t, via: viaTimer}, true)
		}
	}
	if hasPeer {
		if q, ok := r.inbox.takeQueued(); ok {
			return r.finishSelection(selection, "peer", q.selectionLaneSource, q, true)
		}
	}
	if selection != nil && (hasTimer || hasPeer) && selection.Unavailable == "" {
		selection.Unavailable = "dequeue_unavailable"
	}
	return r.finishSelection(selection, "none", 0, queued{}, false)
}

// processOne handles one input; it reports false when there was none.
func (r *Runner) processOne() bool {
	if !r.running.Load() || r.Halted() != nil || r.manualStepPending {
		return false
	}
	if r.settleNextHeight() {
		return true
	}
	if r.Halted() != nil {
		return false
	}
	q, ok := r.next()
	if !ok {
		return false
	}
	if !r.deferManualStep(q) {
		r.handle(q)
	}
	return true
}

// stepCtx carries what the output execution of one step needs.
type stepCtx struct {
	startGens                   []uint64
	retry                       *retryStepContext
	q                           queued
	step                        uint64
	output                      uint64 // original one-based output, retained through own-message signing
	outs                        []consensus.Output
	env                         []envAnswer
	seqIn                       types.Height
	receiveBefore, receiveAfter uint64
}

// handle processes one input: WAL record, core step, outputs, end-of-height
// record, journal record and snapshot.
func (r *Runner) handle(q queued) {
	ticket, received, duplicate, receivePreparation := r.beginReceiveCheckSource(q)
	if duplicate {
		r.inbox.dispatchSource(q, "discard")
		r.dispatchInternal(q, "discard")
		r.dispatchSelection(q, "discard")
		r.observeReceiveCompletion(receivePreparation, "discard")
		return
	}
	if r.receiveCache != nil {
		defer r.receiveCache.Cancel(ticket)
	}
	if q.deferred != nil {
		defer func() { p := r.nextHeight; p.mu.Lock(); p.removeLocked(q.deferred); p.mu.Unlock() }()
	}

	r.step++
	step := r.step
	r.stepAt = event.Stamp{Wall: r.d.Clock.Now(), Mono: r.d.Clock.Mono(), Step: &step}
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
	if r.d.WAL != nil && r.validatorHistory == nil {
		var err error
		if q.deferred != nil {
			err = r.writeDeferred(walDeferredInput, q.deferred.record)
		} else {
			_, err = r.appendFunctionalWAL(encodeInput(kind, body), false)
		}
		if err != nil {
			r.halt(err)
			return
		}
	}
	before := r.core.Snapshot()
	var receiveBefore uint64
	if r.d.CoreSteps != nil {
		receiveBefore = r.currentReceiveScopeObservation()
	}
	gens := r.core.AllTimerGens()
	var historyBefore []uint64
	var historyView validatorHistoryView
	functionalSelected := functionalHistorySelected(r.cfg.Core)
	if functionalSelected {
		historyBefore, historyView = r.core.TimerGenerations(), validatorHistoryAdoption(r.core)
	}
	retry := r.roundChangeRetryBefore(q, before, gens)
	r.env.begin(r.validatorHistory == nil)
	outs := r.core.Step(r.env, q.in)
	answers := r.env.end()
	r.cancelValidatorStartBuild()
	historyHeight := false
	if r.validatorHistory != nil {
		var err error
		historyHeight, err = r.prepareValidatorHistoryStep(q, kind, body, answers, outs, historyBefore, historyView)
		if err != nil {
			r.halt(r.validatorHistory.abort(err))
			return
		}
	} else if functionalSelected {
		afterView := validatorHistoryAdoption(r.core)
		previous, _ := historyView.value()
		current, _ := afterView.value()
		historyHeight = historyView.Adopted == 1 && afterView.Adopted == 1 && current.Sequence.Cmp(previous.Sequence) > 0
	}
	if historyHeight {
		r.lastOwn = map[ownKey][]byte{}
		r.floorSkip = map[string]bool{}
	}
	if r.receiveCache != nil {
		r.completeReceiveCheck(ticket, received, outs)
		r.updateReceiveContext(r.core.Snapshot())
	}
	sc := &stepCtx{q: q, step: step, outs: outs, env: answers, seqIn: before.View.Sequence, retry: retry}
	if r.d.CoreSteps != nil {
		sc.receiveBefore, sc.receiveAfter = receiveBefore, r.currentReceiveScopeObservation()
	}
	r.execute(sc)
	if r.Halted() != nil {
		if r.validatorHistory != nil {
			_ = r.validatorHistory.abort(r.Halted())
		}
		return
	}
	if r.validatorHistory != nil {
		if err := r.validatorHistory.finish(); err != nil {
			r.halt(err)
			return
		}
	}
	if historyHeight {
		if jw, ok := r.d.Journal.(interface{ NoteHead(types.Height) }); ok {
			jw.NoteHead(r.env.head.Number)
		}
	}
	after := r.core.Snapshot()
	r.publishSnapshot(after, snapshotStep)
	if r.d.ObservationSeals != nil {
		witnesses := r.core.Snapshot()
		r.d.ObservationSeals(witnesses.ExtraPrepare, witnesses.ExtraCommit)
	}
	if _, ok := q.in.(consensus.NewHead); !functionalSelected && ok && after.Running && (!before.Running || after.View.Sequence.Cmp(before.View.Sequence) != 0) {
		r.endHeight(after, gens)
	}
	r.journalStep(sc, kind, body, after)
	r.observeCoreStep(sc, kind, body, before, after)
	r.inbox.dispatchSource(q, "dispatch")
	r.dispatchInternal(q, "dispatch")
	r.dispatchSelection(q, "dispatch")
	r.observeReceiveCompletion(receivePreparation, "dispatch")
}

// endHeight writes the end-of-height record of the head the core left
// for, prunes the write-ahead log and releases the builder of the height.
func (r *Runner) endHeight(snap *consensus.Snapshot, gens [4]uint64) {
	h := r.env.head
	faultpoint.Hit(r.d.Faults, faultpoint.EndHeightBefore)
	if r.d.WAL != nil {
		b := boundaryRec{From: h.Number.AddUint64(1), Head: h, Validators: snap.Validators, PriorSource: snap.PriorSource, Replayed: true}
		copy(b.Gens[:], gens[:])
		if r.cfg.Core.Improvements.Has(consensus.ValidateRoundProposals) {
			b.LocalTimer, b.LocalGen = true, gens[3]
		}
		rec, err := r.encodeRunnerBoundary(walEndHeight, b)
		if err != nil {
			r.halt(err)
			return
		}
		pos, err := r.appendFunctionalWAL(rec, true)
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
	for index, o := range sc.outs {
		sc.output = uint64(index) + 1
		r.timers.setOwner(r.engineRun, sc.step, uint64(index)+1, "core")
		if r.Halted() != nil {
			return
		}
		switch o := o.(type) {
		case consensus.Broadcast:
			r.broadcast(sc, o)
		case consensus.Relay:
			if r.d.Transport != nil {
				plan := r.d.Transport.GossipTargets(o.Validators, uint64(o.Code), o.Payload, event.CauseRelay)
				r.emit(event.Record{Kind: event.RelayTargets, Fields: map[string]any{
					"code": uint64(o.Code), "dedup_key": codec.DedupKey(o.Payload).Hex(),
					"available": plan.Available, "candidates": addressTexts(plan.Candidates), "targets": addressTexts(plan.Targets), "suppressed": addressTexts(plan.Suppressed), "output_index": uint64(index) + 1}}, &sc.step)
				if len(plan.Targets) > 0 {
					r.sendEvent(sc, uint64(o.Code), o.Payload, event.CauseRelay, nil)
				}
			}
		case consensus.Schedule:
			r.appendInternal(o.In, "schedule", uint64(index)+1)
		case consensus.ArmTimer:
			r.lastGen[o.Kind] = o.Gen
			if !r.armTimer(o, r.stepAt.Mono) {
				return
			}
			if r.validatorHistory != nil {
				a := o
				r.validatorHistory.installed[o.Kind] = &a
			}
			f := map[string]any{"timer": o.Kind.String(), "duration_ms": o.Duration.Milliseconds(),
				"deadline_mono_ns": int64(r.stepAt.Mono + o.Duration), "gen": o.Gen, "engine_run": r.engineRun}
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
			r.commit(sc, o, uint64(index)+1)
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
					Outcome: o.Class(), Check: check, Row: row, Via: o.Via, Step: sc.step, EngineRun: r.engineRun}})
			}
		case consensus.Event:
			r.emit(o.Record, &sc.step)
		}
	}
}

// broadcast signs, logs, sends and self-delivers an own message.
func (r *Runner) broadcast(sc *stepCtx, b consensus.Broadcast) {
	m := b.Msg
	source := r.newSignerCall(sc, b)
	defer r.finishSignerCall(source)
	if r.d.Signer == nil {
		if r.validatorHistory != nil {
			r.halt(errValidatorHistoryProfile)
			return
		}
		if source != nil {
			source.Result, source.Unavailable = "signer_missing", "source_missing"
		}
		r.appendInternal(consensus.BroadcastFailed{Code: m.Code, View: m.View}, "signer_missing", sc.output)
		return
	}
	sig, err := r.signVoteSource(privval.VoteRequest{Msg: m, SealData: b.SealData, BadBlockReleased: b.BadBlockReleased}, source)
	if err != nil {
		if source != nil {
			source.Result = "refused"
		}
		if !privval.IsRefusal(err) {
			if source != nil {
				source.Result = "signer_error"
			}
			r.halt(err)
			return
		}
		r.refused(sc, m, err)
		return
	}
	c := *m
	c.Seal, c.Signature = sig.Seal, sig.Signature
	if r.validatorHistory != nil && (len(sig.Signature) != 65 || len(sig.Seal) > 96) {
		r.halt(errValidatorHistoryProfile)
		return
	}
	payload, err := codec.EncodeMessage(&c)
	if err != nil {
		if source != nil {
			source.Result, source.Unavailable = "outbound_error", "payload_encoding"
		}
		r.halt(err)
		return
	}
	if err := transport.CheckOutbound(uint64(c.Code), payload); err != nil {
		if r.validatorHistory != nil {
			r.halt(err)
			return
		}
		if source != nil {
			source.Result = "outbound_error"
		}
		r.log.Error("own message not sendable", "code", c.Code, "err", err)
		r.appendInternal(consensus.BroadcastFailed{Code: m.Code, View: m.View}, "outbound", sc.output)
		return
	}
	faultpoint.Hit(r.d.Faults, faultpoint.WALBeforeOwnMsg)
	if r.d.WAL != nil {
		position, err := r.appendFunctionalWAL(encodeOwn(ownRec{Code: uint64(c.Code), Payload: payload}), true)
		if source != nil {
			source.Segment, source.Offset = position.Segment, uint64(position.Offset)
			if err == nil {
				source.WALWritten = 1
				source.Payload = bytes.Clone(payload)
			}
		}
		if err != nil {
			if source != nil {
				source.Result = "wal_error"
			}
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
		if r.currentOwnRetry(sc, b, &c, payload) {
			r.d.Transport.RetryOwnRoundChange(b.Validators, payload, transport.RoundChangeRetryRequest{
				View: b.Retry.View, Generation: b.Retry.Generation, SigningKey: b.Retry.Key,
				PreviousPayload: r.lastOwn[ownKey{code: uint64(c.Code)}],
				Source:          transport.RoundChangeRetrySource{EngineRun: r.engineRun, Step: sc.step, Output: sc.output},
			})
		} else {
			r.d.Transport.Broadcast(b.Validators, uint64(c.Code), payload, cause)
		}
	}
	faultpoint.Hit(r.d.Faults, faultpoint.SendAfter)
	r.sendEvent(sc, uint64(c.Code), payload, cause, &c.View)
	r.lastOwn[ownKey{code: uint64(c.Code)}] = payload
	if r.validatorHistory != nil {
		r.validatorHistory.sent[ownKey{code: uint64(c.Code)}] = bytes.Clone(payload)
	}
	r.appendInternal(consensus.Message{Code: c.Code, Payload: payload, Peer: r.cfg.Core.Self, RecvMono: r.d.Clock.Mono()}, "own", sc.output)
	if source != nil {
		source.Result = "sent"
	}
}

// refused reports a privval refusal to the core as BroadcastFailed.
func (r *Runner) refused(sc *stepCtx, m *codec.Message, err error) {
	if r.d.WAL != nil {
		if _, werr := r.appendFunctionalWAL(encodeOwn(ownRec{Code: uint64(m.Code), Refused: 1, Seq: m.View.Sequence.Big(), Round: m.View.Round.Big()}), false); werr != nil {
			r.halt(werr)
			return
		}
	}
	if r.d.Refused != nil {
		r.d.Refused(uint64(m.Code))
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
	r.appendInternal(consensus.BroadcastFailed{Code: m.Code, View: m.View}, "refusal", sc.output)
}

func (r *Runner) sendEvent(sc *stepCtx, code uint64, payload []byte, cause event.SendCause, view *types.View) {
	if r.d.Events == nil {
		return
	}
	r.emit(sendRecord(code, payload, cause, view), &sc.step)
}

// sendRecord binds the observation to the bytes sent. A view is supplied only
// when the sending path already holds the corresponding message.
func sendRecord(code uint64, payload []byte, cause event.SendCause, view *types.View) event.Record {
	sum := sha256.Sum256(payload)
	key := codec.DedupKey(payload)
	var observed *event.View
	if view != nil {
		observed = event.ViewOf(*view)
	}
	return event.Record{Kind: event.Send, View: observed, Fields: map[string]any{
		"code": code, "dedup_key": "0x" + hex.EncodeToString(key[:]), "payload_sha256": "0x" + hex.EncodeToString(sum[:]), "cause": cause}}
}

// commit logs the commit request and hands the block to the commit
// goroutine.
func (r *Runner) commit(sc *stepCtx, c consensus.Commit, output uint64) {
	faultpoint.Hit(r.d.Faults, faultpoint.CommitBefore)
	if r.d.WAL != nil {
		rec, err := encodeCommit(c.Block, c.Round)
		if err != nil {
			r.halt(err)
			return
		}
		if _, err := r.appendFunctionalWAL(rec, true); err != nil {
			r.halt(err)
			return
		}
	}
	faultpoint.Hit(r.d.Faults, faultpoint.CommitAfter)
	prep, com := sealers(c.Block.Header)
	r.emit(event.Record{Kind: event.FinalizeHandover, Fields: map[string]any{
		"number": c.Block.Header.Number.String(), "hash": hexHash(codec.BlockHash(c.Block.Header)), "round": c.Round.String(),
		"prepared_sealers": prep, "committed_sealers": com}}, &sc.step)
	j := commitJob{block: c.Block, round: c.Round}
	if r.d.FinalizeSources != nil {
		j.source = finalizeSourceOwner{engine: r.engineRun, step: sc.step, output: output}
	}
	r.commitMu.Lock()
	j.at = r.d.Clock.Mono()
	before := len(r.commitQ)
	r.commitQ = append(r.commitQ, j)
	observation := r.finalizeSource("enqueue", j, before, len(r.commitQ), false, "", nil)
	if observation != nil {
		r.commitQ[len(r.commitQ)-1].source.task = observation.Task
	}
	r.commitCond.Signal()
	r.commitMu.Unlock()
	r.publishFinalize(observation)
}

func sealers(h *types.Header) (prepared, committed []uint32) {
	prepared, committed = []uint32{}, []uint32{}
	x, err := codec.DecodeConsensusExtra(h)
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
	if r.manualCommitPending.Load() || len(r.commitQ) == 0 {
		r.commitMu.Unlock()
		return false
	}
	j := r.commitQ[0]
	before := len(r.commitQ)
	r.commitQ = r.commitQ[1:]
	observation := r.finalizeSource("dequeue", j, before, len(r.commitQ), false, "", nil)
	r.commitMu.Unlock()
	r.publishFinalize(observation)
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
		before := len(r.commitQ)
		r.commitQ = r.commitQ[1:]
		observation := r.finalizeSource("dequeue", j, before, len(r.commitQ), false, "", nil)
		r.commitMu.Unlock()
		r.publishFinalize(observation)
		r.finalize(j)
	}
}

// finalize calls the application and queues the result for the core.
func (r *Runner) finalize(j commitJob) {
	r.publishFinalize(r.finalizeSource("enter", j, 0, 0, false, "", nil))
	if r.cfg.Manual {
		if app, ok := r.d.App.(ManualFinalizer); ok {
			r.manualCommitPending.Store(true)
			var once sync.Once
			app.FinalizeBlockManual(j.block, j.round, func(err error) { once.Do(func() { r.finalizeDone(j, err); r.manualCommitPending.Store(false) }) })
			return
		}
	}
	r.finalizeDone(j, r.callFinalize(j))
}

func (r *Runner) finalizeDone(j commitJob, err error) {
	r.publishFinalize(r.finalizeSource("return", j, 0, 0, err != nil, "", nil))
	hash := codec.BlockHash(j.block.Header)
	f := map[string]any{"number": j.block.Header.Number.String(), "hash": hexHash(hash), "ok": err == nil,
		"duration_ms": (r.d.Clock.Mono() - j.at).Milliseconds()}
	if err != nil {
		f["error_class"] = err.Error()
	}
	r.emit(event.Record{Kind: event.CommitResult, Fields: f}, nil)
	queueRun := r.finalizeQueueRun()
	r.appMu.Lock()
	result := consensus.CommitResult{Hash: hash, Err: err}
	if r.cfg.Core.Improvements.Has(consensus.WatchCommittedImport) || r.cfg.Core.Improvements.Has(consensus.AdvanceOnCommitFailure) {
		result.View = &types.View{Sequence: j.block.Header.Number, Round: j.round}
	}
	observation := r.appendAppLocked(result)
	notification := r.finalizeSource("notify", j, 0, 0, err != nil, queueRun, observation)
	r.appMu.Unlock()
	r.publishAppQueue(observation)
	r.publishFinalize(notification)
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
		if a.call.Kind == inputlog.EnvValidatorsAt && !r.cfg.Core.Improvements.Has(consensus.BindPriorHead) && !functionalHistorySelected(r.cfg.Core) {
			continue
		}
		b, err := inputlog.EncodeEnv(a.call)
		if err == nil {
			envs = append(envs, b)
		}
	}
	if sc.q.deferred != nil {
		d := sc.q.deferred.record
		var err error
		body, err = inputlog.EncodeDeferredMessage(d.message(), inputlog.CaptureOrigin{Run: d.CaptureRun, Capture: d.Capture})
		if err != nil {
			r.log.Warn("journal deferred encoding failed", "err", err)
			return
		}
		kind = inputlog.KindDeferredMessage
	} else if m, ok := sc.q.in.(consensus.Message); ok && sc.q.capture != 0 {
		var err error
		body, err = inputlog.EncodeCapturedMessage(m, sc.q.capture)
		if err != nil {
			r.log.Warn("journal capture encoding failed", "err", err)
			return
		}
		kind = inputlog.KindCapturedMessage
	}
	rec := &journal.StepRec{Entry: &journal.StepMoment{Mono: r.stepAt.Mono, WallNs: r.stepAt.Wall.UnixNano()}, EngineRun: r.engineRun, Step: sc.step, Mono: r.d.Clock.Mono(), WallNs: r.d.Clock.Now().UnixNano(),
		InputKind: kind, Input: body, Via: sc.q.via, Env: envs, ValsetDigest: consensus.ValsetDigest(after.Validators), OutDigest: d}
	if sc.startGens != nil {
		rec.TimerGens = append([]uint64(nil), sc.startGens...)
	}
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

func addressTexts(addresses []types.Address) []string {
	out := make([]string, len(addresses))
	for i, a := range addresses {
		out[i] = strings.ToLower(a.Hex())
	}
	return out
}
