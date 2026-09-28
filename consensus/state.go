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
// The state machine of this package follows the event handlers of
// consensus/wbft/core of go-stablenet (commit 740526d03), which are derived
// from quorum/consensus/istanbul/qbft/core. Timers, signing and sending are
// outputs here instead of calls.

package consensus

import (
	"bytes"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// State is the consensus state of one node: the Node record of A-05 section
// 3.1 plus the timer generations. It is not safe for concurrent use; the
// runner calls Step from one goroutine.
type State struct {
	opt     Options
	running bool

	// Timer generations. A generation increases with every ArmTimer of its
	// kind and is never reset, so an expiry of a timer of an earlier run is
	// recognised after a restart.
	gen        [3]uint64
	roundLive  bool // the round timer of generation gen[RoundTimer] is armed
	futureLive bool // the future timer of generation gen[FutureTimer] is armed
	future     *Verified

	cur          *roundState
	state        StateName
	validators   *validator.Set
	proposer     int // index in validators, -1 for none
	certificate  []*Verified
	rcs          *roundChangeSet
	pending      []pendingRequest
	pendingSeq   uint64
	backlog      map[types.Address]*backlogQueue
	extraPrepare map[types.Address]*Verified
	extraCommit  map[types.Address]*Verified
	prior        priorState
	head         HeadInfo
}

// roundState is RoundState of A-05 section 3.1.
type roundState struct {
	view           types.View
	preprepare     *Verified
	prepares       map[types.Address]*Verified
	commits        map[types.Address]*Verified
	preparedRound  *types.Round
	preparedBlock  *types.Block
	pendingRequest *types.Block
	preprepareSent types.Round
}

func newRoundState(view types.View) *roundState {
	return &roundState{
		view:     view,
		prepares: make(map[types.Address]*Verified),
		commits:  make(map[types.Address]*Verified),
	}
}

// priorState is PriorState of A-05 section 3.1.
type priorState struct {
	round      types.Round
	proposal   *types.Block
	validators *validator.Set
}

type pendingRequest struct {
	block *types.Block
	prio  int64
	seq   uint64
}

// NewState returns a stopped core. Step(Start) starts it.
func NewState(opt Options) *State {
	if opt.BacklogLimit < MinBacklogLimit {
		opt.BacklogLimit = MinBacklogLimit
	}
	s := &State{opt: opt}
	s.reset()
	return s
}

// reset discards the consensus state (WBFT-SM-004). Timer generations are
// kept.
func (s *State) reset() {
	s.cur = nil
	s.state = AcceptRequest
	s.validators = nil
	s.proposer = -1
	s.certificate = nil
	s.rcs = newRoundChangeSet()
	s.pending = nil
	s.backlog = make(map[types.Address]*backlogQueue)
	s.extraPrepare = make(map[types.Address]*Verified)
	s.extraCommit = make(map[types.Address]*Verified)
	s.prior = priorState{}
	s.roundLive = false
	s.futureLive = false
	s.future = nil
}

// Running reports whether the core has been started and not stopped.
func (s *State) Running() bool { return s.running }

// Options returns the options the core was created with.
func (s *State) Options() Options { return s.opt }

// step collects the outputs of one Step.
type step struct {
	s   *State
	env Env
	out []Output
}

func (st *step) emit(o Output) { st.out = append(st.out, o) }

// Step applies one input and returns the outputs to execute, in order. While
// the core is stopped every input other than Start is ignored.
//
// Spec: WBFT-SM-001
func (s *State) Step(env Env, in Input) []Output {
	st := &step{s: s, env: env}
	if !s.running {
		if _, ok := in.(Start); ok {
			st.onStart()
		}
		return st.out
	}
	if s.cur == nil {
		// Start found no head: only Start, Stop and NewHead can move on.
		switch in.(type) {
		case Start, Stop, NewHead:
		default:
			return st.out
		}
	}
	switch v := in.(type) {
	case Start:
		st.onStart()
	case Stop:
		st.onStop()
	case NewHead:
		st.startNewRound(types.Round{}, causeNewHead)
	case Request:
		st.onRequest(v.Block)
	case Message:
		st.onMessage(v)
	case Replay:
		st.onReplay(v.Msg)
	case Timeout:
		st.onTimeout(v)
	case BroadcastFailed:
		st.onBroadcastFailed(v)
	case CommitResult, PeerConnected:
		// The reference does not learn the import result and has no
		// reconnect path; nothing changes.
	}
	return st.out
}

// onStart initialises the state and enters the first view.
//
// Spec: WBFT-SM-004, WBFT-SM-008
func (st *step) onStart() {
	st.s.reset()
	st.s.running = true
	st.startNewRound(types.Round{}, causeStart)
}

// onStop cancels the timers and discards the state.
//
// Spec: WBFT-SM-009
func (st *step) onStop() {
	st.emit(CancelTimers{Kinds: AllTimers})
	st.s.reset()
	st.s.running = false
}

// onBroadcastFailed undoes the effect of a PRE-PREPARE that was not sent:
// preprepare_sent is set only after a successful broadcast.
//
// Spec: WBFT-SM-036
func (st *step) onBroadcastFailed(v BroadcastFailed) {
	s := st.s
	if v.Code == codec.CodePreprepare && s.cur != nil && v.View.Cmp(s.cur.view) == 0 {
		s.cur.preprepareSent = types.Round{}
	}
}

// quorum is Q of the current validator set.
func (s *State) quorum() int { return s.validators.Quorum() }

// isProposer reports whether a is the proposer of the current set.
func (s *State) isProposer(a types.Address) bool {
	if s.validators == nil {
		return false
	}
	return s.validators.IsProposer(s.proposer, a)
}

// proposerAddress returns the address of the proposer, or the zero address.
func (s *State) proposerAddress() types.Address {
	if s.validators == nil || s.proposer < 0 || s.proposer >= s.validators.Len() {
		return types.Address{}
	}
	return s.validators.At(s.proposer).Addr
}

// sortedAddrs returns the keys of m in ascending byte order.
func sortedAddrs[V any](m map[types.Address]V) []types.Address {
	keys := make([]types.Address, 0, len(m))
	for a := range m { //wbft:unordered the keys are sorted below
		keys = append(keys, a)
	}
	slices.SortStableFunc(keys, func(a, b types.Address) int { return bytes.Compare(a[:], b[:]) })
	return keys
}

// blockHash is block_hash of a proposal.
func blockHash(b *types.Block) types.Hash { return codec.BlockHash(b.Header) }
