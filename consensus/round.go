// Copyright 2017 The go-ethereum Authors
// Copyright 2024 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// startNewRound, updateRoundState, setState and the timer procedures follow
// consensus/wbft/core/core.go and request.go of go-stablenet (commit
// 740526d03), which are derived from quorum/consensus/istanbul/qbft/core.

package consensus

import (
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// Causes of a start_new_round call, for ROUND_ENTER events.
const (
	causeStart    = event.CauseStart
	causeNewHead  = event.CauseNewHead
	causeTimeout  = event.CauseTimeout
	causeFPlusOne = event.CauseFPlusOne
)

// Branches of start_new_round.
const (
	branchInitial     = "INITIAL"
	branchCatchUp     = "CATCH_UP"
	branchRoundChange = "ROUND_CHANGE"
)

// config returns config_at(n); a core without a configuration uses the zero
// parameters.
func (s *State) config(n types.Height) types.Params {
	if s.opt.Config == nil {
		return types.Params{}
	}
	return s.opt.Config.ConfigAt(n)
}

// startNewRound is start_new_round(node, round): it reads the head, selects
// the branch, updates the round state, the validators and the proposer, runs
// set_state(AcceptRequest), resets the round-change set, the prepared
// certificate and the extra seals by the requested round, notifies the block
// builder and starts the round timer. It returns without any change when no
// branch applies.
//
// Spec: WBFT-SM-022, WBFT-SM-023, WBFT-SM-026, WBFT-SM-027, WBFT-SM-028, WBFT-SM-029, WBFT-SM-030
func (st *step) startNewRound(round types.Round, cause string) {
	s := st.s
	head := st.env.Head()
	s.head = head
	last := head.Header
	if last == nil {
		return
	}

	var branch string
	switch {
	case s.cur == nil:
		branch = branchInitial
	case last.Number.Cmp(s.cur.view.Sequence) >= 0:
		branch = branchCatchUp
	case sameAsPrevious(last.Number, s.cur.view.Sequence):
		if round.IsZero() || round.Cmp(s.cur.view.Round) < 0 {
			return
		}
		branch = branchRoundChange
	default:
		return
	}

	var newView types.View
	var nextVS *validator.Set
	if branch == branchRoundChange {
		newView = types.View{Sequence: s.cur.view.Sequence, Round: round}
		nextVS = s.validators
	} else {
		next := last.Number.AddUint64(1)
		newView = types.View{Sequence: next}
		nextVS = st.validatorsAt(next, last)
		if s.cur != nil {
			st.addEffectiveSealsToExtraSeals()
		}
		s.pruneSeen(next)
	}
	st.updateRoundState(nextVS, newView, branch == branchRoundChange)
	s.proposer = s.validators.CalcProposer(head.Proposer, newView.Round.RefLow64()) //wbft:low64 HH-71
	st.emit(Event{Record: event.Record{
		Kind: event.RoundEnter,
		View: event.ViewOf(newView),
		Fields: map[string]any{
			"branch":          branch,
			"cause":           cause,
			"requested_round": round.String(),
			"proposer":        hexAddr(s.proposerAddress()),
			"is_proposer":     s.isProposer(s.opt.Self),
			"valset_digest":   hexHash(ValsetDigest(s.validators)),
		},
	}})
	st.setState(AcceptRequest)
	if round.RefLow64() == 0 { //wbft:low64 HH-70
		s.certificate = nil
		s.rcs = newRoundChangeSet()
		st.clearExtraSeals(last.Number)
	} else {
		s.rcs.clearLowerThan(round)
	}
	s.rcs.newRound(round)
	// Spec: WBFT-PARAM-053 (block period for the next block: latest + 1)
	st.emit(RequestBuild{
		Height:      newView.Sequence,
		Round:       round,
		HeadTime:    last.Time,
		BlockPeriod: s.config(last.Number.AddUint64(1)).BlockPeriodSeconds,
	})
	st.startRoundTimer()
}

// sameAsPrevious reports last == int64(seq) - 1: the right side is computed
// from the low 64 bits of seq read as a signed integer, in 64-bit signed
// arithmetic, and compared with the full value of last.
func sameAsPrevious(last, seq types.Height) bool {
	v := seq.RefLowInt64() //wbft:low64 HH-06
	if v == math.MinInt64 {
		v = math.MaxInt64 // v - 1 wraps around
	} else {
		v--
	}
	if v < 0 {
		return false
	}
	return last.CmpUint64(uint64(v)) == 0
}

// validatorsAt returns validators_at(next) for the child of last; a failed
// lookup gives an empty set, with which the node sends nothing.
//
// Spec: WBFT-SM-026
func (st *step) validatorsAt(next types.Height, last *types.Header) *validator.Set {
	vs, err := st.env.ValidatorsAt(next, codec.BlockHash(last))
	if err != nil || vs == nil {
		var policy types.ProposerPolicy
		if p := st.s.config(last.Number).ProposerPolicy; p != nil {
			policy = *p
		}
		vs, _ = validator.NewSet(nil, nil, policy)
	}
	return vs
}

// updateRoundState replaces the round state. A round change within the
// sequence carries the last PRE-PREPARE, the lock and the pending request,
// after releasing a lock on a bad block; a new sequence first records the
// prior state and starts empty.
//
// Spec: WBFT-SM-005, WBFT-SM-006, WBFT-SM-024, WBFT-SM-025
func (st *step) updateRoundState(nextVS *validator.Set, view types.View, roundChange bool) {
	s := st.s
	if roundChange && s.cur != nil {
		c := s.cur
		if c.preparedBlock != nil && st.env.IsBadBlock(blockHash(c.preparedBlock)) {
			c.preparedRound = nil
			c.preparedBlock = nil
			c.badBlockReleased = true
			st.clearExtraSeals(c.view.Sequence.AddUint64(1))
		}
		n := newRoundState(view)
		n.preprepare = c.preprepare
		n.preparedRound = c.preparedRound
		n.preparedBlock = c.preparedBlock
		n.pendingRequest = c.pendingRequest
		n.badBlockReleased = c.badBlockReleased
		s.cur = n
	} else {
		if s.cur != nil {
			s.prior.round = s.cur.view.Round
			if s.cur.preprepare != nil {
				s.prior.proposal = s.cur.preprepare.Msg.Proposal
			}
			if s.validators != nil {
				s.prior.validators = s.validators
			}
		}
		s.cur = newRoundState(view)
	}
	s.validators = nextVS
}

// setState changes the consensus state, replays stored requests when the
// state is AcceptRequest, and replays the backlog on every call.
//
// Spec: WBFT-SM-027, WBFT-SM-073
func (st *step) setState(to StateName) {
	s := st.s
	if s.state != to {
		st.emit(Event{Record: event.Record{
			Kind:   event.StateChange,
			View:   event.ViewOf(s.cur.view),
			Fields: map[string]any{"from": s.state.String(), "to": to.String()},
		}})
		s.state = to
	}
	if to == AcceptRequest {
		st.processPendingRequests()
	}
	st.processBacklog()
}

// startRoundTimer stops the three timers and arms the round timer for the
// current view with round_timeout(config_at(sequence), round).
//
// Spec: WBFT-SM-030, WBFT-SM-075, WBFT-TIMER-010, WBFT-TIMER-013
func (st *step) startRoundTimer() {
	s := st.s
	st.emit(CancelTimers{Kinds: AllTimers})
	s.futureLive = false
	s.future = nil
	s.gen[RoundTimer]++
	s.roundLive = true
	// Spec: WBFT-PARAM-053 (timeouts at the current sequence)
	d, _ := RoundTimeout(s.config(s.cur.view.Sequence), s.cur.view.Round)
	st.emit(ArmTimer{Kind: RoundTimer, View: s.cur.view, Round: s.cur.view.Round, Duration: d, Gen: s.gen[RoundTimer]})
}

// armRetryTimer arms the retry timer for RT(h) with the current round.
//
// Spec: WBFT-TIMER-020
func (st *step) armRetryTimer() {
	s := st.s
	s.gen[RetryTimer]++
	d := time.Duration(s.config(s.cur.view.Sequence).RequestTimeoutMs) * time.Millisecond
	st.emit(ArmTimer{Kind: RetryTimer, View: s.cur.view, Round: s.cur.view.Round, Duration: d, Gen: s.gen[RetryTimer]})
}

// armFutureTimer arms the future-proposal timer for m, replacing an earlier
// one.
//
// Spec: WBFT-SM-038, WBFT-TIMER-032
func (st *step) armFutureTimer(m *Verified, d time.Duration) {
	s := st.s
	s.gen[FutureTimer]++
	s.futureLive = true
	s.future = m
	st.emit(ArmTimer{Kind: FutureTimer, View: m.Msg.View, Round: m.Msg.View.Round, Duration: d, Gen: s.gen[FutureTimer], Digest: blockHash(m.Msg.Proposal), Msg: m})
	st.emit(Event{Record: event.Record{
		Kind:   event.ProposalDeferred,
		View:   event.ViewOf(m.Msg.View),
		Fields: map[string]any{"digest": hexHash(blockHash(m.Msg.Proposal)), "wait_ns": int64(d)},
	}})
}

// onTimeout handles the expiry of a timer.
//
// Spec: WBFT-SM-075, WBFT-SM-077, WBFT-TIMER-014, WBFT-TIMER-015, WBFT-TIMER-021, WBFT-TIMER-031, WBFT-TIMER-032
func (st *step) onTimeout(t Timeout) {
	s := st.s
	switch t.Kind {
	case RoundTimer:
		// An expiry of a cancelled or superseded round timer has no effect.
		if !s.roundLive || t.Gen != s.gen[RoundTimer] {
			return
		}
		next := s.cur.view.Round.AddUint64(1)
		st.startNewRound(next, causeTimeout)
		st.broadcastRoundChange(next)
	case RetryTimer:
		// Retry expiries are not cancellable once queued.
		st.broadcastRoundChange(t.Round)
	case FutureTimer:
		// An expiry that carries its PRE-PREPARE was queued before the
		// timer was cancelled or replaced (a cancelled timer that had not
		// fired produces no expiry): the reference processes it, and so
		// does the core. An expiry without its message stands for the
		// deferred PRE-PREPARE of the armed timer.
		m := t.Msg
		if m == nil {
			if !s.futureLive || t.Gen != s.gen[FutureTimer] || s.future == nil {
				return
			}
			m = s.future
		}
		if t.Gen == s.gen[FutureTimer] {
			s.futureLive = false
			s.future = nil
		}
		st.emit(Schedule{In: Replay{Msg: m}})
	}
}

// checkRequest is check_request.
func (s *State) checkRequest(b *types.Block) Class {
	if b == nil || b.Header == nil || s.cur == nil {
		return Invalid
	}
	switch c := s.cur.view.Sequence.Cmp(b.Header.Number); {
	case c > 0:
		return Old
	case c < 0:
		return Future
	}
	return Process
}

// onRequest handles a proposal of the block builder: a future one is stored,
// a current one becomes the pending request and is proposed in round 0.
//
// Spec: WBFT-SM-031, WBFT-SM-032
func (st *step) onRequest(b *types.Block) {
	s := st.s
	switch s.checkRequest(b) {
	case Future:
		st.storeRequest(b)
		return
	case Process:
	default:
		return
	}
	s.cur.pendingRequest = b
	if s.state == AcceptRequest && s.cur.view.Round.RefLow64() == 0 { //wbft:low64 HH-70
		if s.opt.Improvements.Has(OneRound0Proposal) && s.cur.preprepareSentValid {
			return
		}
		st.sendPreprepare(b, nil, nil)
	}
}

// storeRequest queues a future request with priority -int64(number).
//
// Spec: WBFT-SM-031
func (st *step) storeRequest(b *types.Block) {
	s := st.s
	prio := -b.Header.Number.RefLowInt64() //wbft:low64 HH-04
	s.pendingSeq++
	r := pendingRequest{block: b, prio: prio, seq: s.pendingSeq}
	i := 0
	for i < len(s.pending) && !before(r.prio, r.seq, s.pending[i].prio, s.pending[i].seq) {
		i++
	}
	s.pending = append(s.pending[:i], append([]pendingRequest{r}, s.pending[i:]...)...)
}

// before orders priority queue entries: higher priority first, ties in
// insertion order.
func before(p1 int64, s1 uint64, p2 int64, s2 uint64) bool {
	if p1 != p2 {
		return p1 > p2
	}
	return s1 < s2
}

// processPendingRequests replays the stored requests of the current sequence
// and stops at the first future one.
//
// Spec: WBFT-SM-033
func (st *step) processPendingRequests() {
	s := st.s
	for len(s.pending) > 0 {
		r := s.pending[0]
		switch s.checkRequest(r.block) {
		case Future:
			return
		case Process:
			s.pending = s.pending[1:]
			st.emit(Schedule{In: Request{Block: r.block}})
		default:
			s.pending = s.pending[1:]
		}
	}
}
