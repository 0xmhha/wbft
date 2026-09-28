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
// broadcastRoundChange, handleRoundChangeMsg and roundChangeSet follow
// consensus/wbft/core/roundchange.go of go-stablenet (commit 740526d03),
// which is derived from quorum/consensus/istanbul/qbft/core/roundchange.go.

package consensus

import (
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// roundChangeSet is RoundChangeSet of A-05 section 3.1, keyed by the low 64
// bits of the round.
type roundChangeSet struct {
	rounds map[uint64]*roundChanges
}

type roundChanges struct {
	msgs         map[types.Address]*Verified
	highestRound *types.Round
	highestBlock *types.Block
	highestJust  []*Verified
}

func newRoundChangeSet() *roundChangeSet {
	return &roundChangeSet{rounds: make(map[uint64]*roundChanges)}
}

func roundKey(r types.Round) uint64 {
	return r.RefLow64() //wbft:low64 HH-73
}

func (rcs *roundChangeSet) entry(k uint64) *roundChanges {
	e := rcs.rounds[k]
	if e == nil {
		e = &roundChanges{msgs: make(map[types.Address]*Verified)}
		rcs.rounds[k] = e
	}
	return e
}

// sortedKeys returns the round keys in ascending order.
func (rcs *roundChangeSet) sortedKeys() []uint64 {
	keys := make([]uint64, 0, len(rcs.rounds))
	for k := range rcs.rounds { //wbft:unordered the keys are sorted below
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// newRound creates the entry of round r if it is missing.
//
// Spec: WBFT-SM-056
func (rcs *roundChangeSet) newRound(r types.Round) { rcs.entry(roundKey(r)) }

// add stores m for round r, replacing an earlier ROUND-CHANGE of its source,
// and raises the highest prepared round of r when pr is higher and the
// PREPAREs match.
//
// Spec: WBFT-SM-055
func (rcs *roundChangeSet) add(r types.Round, m *Verified, pr *types.Round, pb *types.Block, prepares []*Verified, quorum int) {
	e := rcs.entry(roundKey(r))
	e.msgs[m.Source] = m
	if pr != nil && (e.highestRound == nil || pr.Cmp(*e.highestRound) > 0) {
		if hasMatchingRoundChangeAndPrepares(summarizeRoundChange(m), summarizePrepares(prepares), quorum) {
			e.highestRound = pr
			e.highestBlock = pb
			e.highestJust = prepares
		}
	}
}

// higherRoundSenders counts the distinct sources of ROUND-CHANGEs for any
// round above r.
//
// Spec: WBFT-SM-056
func (rcs *roundChangeSet) higherRoundSenders(r types.Round) int {
	k0 := roundKey(r)
	seen := make(map[types.Address]bool)
	for k, e := range rcs.rounds { //wbft:unordered only the number of distinct sources is used
		if k > k0 {
			for a := range e.msgs { //wbft:unordered only the number of distinct sources is used
				seen[a] = true
			}
		}
	}
	return len(seen)
}

// countAt counts the ROUND-CHANGEs stored for round r.
func (rcs *roundChangeSet) countAt(r types.Round) int {
	if e := rcs.rounds[roundKey(r)]; e != nil {
		return len(e.msgs)
	}
	return 0
}

// minRoundAbove returns the smallest round key above r, including keys
// without messages, or r when there is none.
//
// Spec: WBFT-SM-056
func (rcs *roundChangeSet) minRoundAbove(r types.Round) types.Round {
	k0 := roundKey(r)
	for _, k := range rcs.sortedKeys() {
		if k > k0 {
			return types.RoundFromUint64(k)
		}
	}
	return r
}

// clearLowerThan deletes every round below r and every round without
// messages.
//
// Spec: WBFT-SM-056
func (rcs *roundChangeSet) clearLowerThan(r types.Round) {
	k0 := roundKey(r)
	for _, k := range rcs.sortedKeys() {
		if len(rcs.rounds[k].msgs) == 0 || k < k0 {
			delete(rcs.rounds, k)
		}
	}
}

// broadcastRoundChange is broadcast_round_change: it first arms the retry
// timer with the current round, then sends nothing for a target below the
// current round, and otherwise sends ROUND-CHANGE for the target with the lock
// and the prepared certificate.
//
// Spec: WBFT-SM-052, WBFT-SM-053
func (st *step) broadcastRoundChange(round types.Round) {
	s := st.s
	st.armRetryTimer()
	c := s.cur
	if c.view.Round.Cmp(round) > 0 {
		return
	}
	m := &codec.Message{
		Code:          codec.CodeRoundChange,
		View:          types.View{Sequence: c.view.Sequence, Round: round},
		PreparedRound: c.preparedRound,
		PreparedBlock: c.preparedBlock,
	}
	if c.preparedBlock != nil {
		m.PreparedDigest = blockHash(c.preparedBlock)
	}
	if s.certificate != nil {
		m.Prepares = sortByEncoding(messagesOf(s.certificate), codec.EncodeMessage)
	}
	st.broadcast(m, nil)
}

// handleRoundChange stores a ROUND-CHANGE of the current sequence and applies
// the F+1 rule, or else the proposer's quorum rule.
//
// Spec: WBFT-SM-054, WBFT-SM-057, WBFT-SM-058, WBFT-SM-059, WBFT-SM-060
func (st *step) handleRoundChange(v *Verified) (bool, int) {
	s := st.s
	m := v.Msg
	r0 := s.cur.view.Round
	if m.View.Round.Cmp(r0) >= 0 {
		var pr *types.Round
		var pb *types.Block
		var ps []*Verified
		if m.PreparedRound != nil && m.PreparedBlock != nil && len(m.Prepares) > 0 {
			if m.PreparedBlock.Header.Number.Cmp(s.cur.view.Sequence) != 0 {
				return false, rowRCOtherSequence
			}
			if blockHash(m.PreparedBlock) != m.PreparedDigest {
				return false, rowRCOtherSequence
			}
			pr, pb, ps = m.PreparedRound, m.PreparedBlock, v.prepares()
		}
		s.rcs.add(m.View.Round, v, pr, pb, ps, s.quorum())
	}
	num := s.rcs.higherRoundSenders(r0)
	if validator.InFPlusOneWindow(num, s.validators.Len()) {
		target := s.rcs.minRoundAbove(r0)
		st.emitQuorum("F_PLUS_ONE", num)
		st.startNewRound(target, causeFPlusOne)
		st.broadcastRoundChange(target)
		return true, rowRCFPlusOne
	}
	if s.rcs.countAt(r0) >= s.quorum() && s.isProposer(s.opt.Self) && s.cur.preprepareSent.Cmp(r0) < 0 {
		st.emitQuorum("ROUND_CHANGE", s.rcs.countAt(r0))
		e := s.rcs.rounds[roundKey(r0)]
		proposal := e.highestBlock
		if proposal == nil {
			if s.cur.pendingRequest == nil {
				return false, rowRCNoProposal
			}
			proposal = s.cur.pendingRequest
		}
		rcs := make([]*Verified, 0, len(e.msgs))
		for _, a := range sortedAddrs(e.msgs) {
			rcs = append(rcs, e.msgs[a])
		}
		ps := e.highestJust
		if !IsJustified(blockHash(proposal), s.cur.view, summarizeRoundChanges(rcs), summarizePrepares(ps), s.quorum()) {
			return true, rowRCNotJustified
		}
		st.sendPreprepare(proposal, rcs, ps)
		return true, rowRCProposed
	}
	return true, rowRCStored
}
