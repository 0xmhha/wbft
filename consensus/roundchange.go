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
	"errors"
	"slices"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// roundChangeSet is RoundChangeSet of A-05 section 3.1, keyed by the low 64
// bits of the round.
type roundChangeSet struct {
	rounds  map[uint64]*roundChanges
	refresh bool
}

type roundChanges struct {
	msgs         map[types.Address]*Verified
	highestRound *types.Round
	highestBlock *types.Block
	highestJust  []*Verified
	prepared     map[types.Address]roundPrepared
}

type roundPrepared struct {
	round *types.Round
	block *types.Block
	just  []*Verified
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
		if rcs.refresh {
			e.prepared = make(map[types.Address]roundPrepared)
		}
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

// add stores m for round r, replacing an earlier ROUND-CHANGE of its source.
// The default raises the cached prepared round only. The refresh policy
// selects from the current matching certificates after every replacement.
//
// Spec: WBFT-SM-055
func (rcs *roundChangeSet) add(r types.Round, m *Verified, pr *types.Round, pb *types.Block, prepares []*Verified, quorum int) {
	e := rcs.entry(roundKey(r))
	e.msgs[m.Source] = m
	if rcs.refresh {
		delete(e.prepared, m.Source)
		if pr != nil && hasMatchingRoundChangeAndPrepares(summarizeRoundChange(m), summarizePrepares(prepares), quorum) {
			e.prepared[m.Source] = roundPrepared{round: pr, block: pb, just: prepares}
		}
		e.refreshHighest()
		return
	}
	if pr != nil && (e.highestRound == nil || pr.Cmp(*e.highestRound) > 0) {
		if hasMatchingRoundChangeAndPrepares(summarizeRoundChange(m), summarizePrepares(prepares), quorum) {
			e.highestRound = pr
			e.highestBlock = pb
			e.highestJust = prepares
		}
	}
}

// refreshHighest considers only current entries, with address order resolving
// equal prepared rounds independently of message arrival order.
func (e *roundChanges) refreshHighest() {
	e.highestRound, e.highestBlock, e.highestJust = nil, nil, nil
	for _, source := range sortedAddrs(e.prepared) {
		p := e.prepared[source]
		if e.highestRound == nil || p.round.Cmp(*e.highestRound) > 0 {
			e.highestRound, e.highestBlock, e.highestJust = p.round, p.block, p.just
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
	st.broadcastRoundChangeWithRetry(round, nil)
}

func (st *step) broadcastRoundChangeWithRetry(round types.Round, expiry *Timeout) {
	s := st.s
	if s.opt.RoundChangeRetry == nil {
		st.armRetryTimer()
	}
	c := s.cur
	if c.view.Round.Cmp(round) > 0 {
		if s.opt.RoundChangeRetry != nil {
			// A legacy stale expiry may rearm, but never resets or shortens
			// the current candidate's backoff using the old target round.
			st.armRetryTimer()
		}
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
	if certificate := s.preparedCertificate(); certificate != nil {
		m.Prepares = sortByEncoding(messagesOf(certificate), codec.EncodeMessage)
	}
	released := s.opt.Improvements.Has(BadBlockReleaseMark) && c.badBlockReleased && c.preparedBlock == nil
	var retry *RoundChangeRetryIntent
	if s.opt.RoundChangeRetry != nil {
		if m.View.Cmp(c.view) == 0 {
			if key, err := roundChangeRetryKeyWithDomain(m, s.opt.RoundChangeDomain); err == nil {
				r := &s.roundChangeRetry
				same := r.valid && r.view.Cmp(c.view) == 0 && r.key == key
				r.prepare(c.view, key, expiry != nil)
				if expiry != nil && same {
					retry = &RoundChangeRetryIntent{View: c.view, Generation: expiry.Gen, Key: key}
				}
			}
		}
		st.armRetryTimer()
	}
	st.emitBroadcast(Broadcast{Msg: m, BadBlockReleased: released, Retry: retry})
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
	threshold := validator.FPlusOneThreshold(s.validators.Len())
	follow := num == threshold
	if s.opt.Improvements.Has(FollowHigherRoundChanges) {
		follow = num >= threshold
	}
	if follow {
		target := s.rcs.minRoundAbove(r0)
		st.emitQuorum("F_PLUS_ONE", num)
		newHeight := st.startNewRound(target, causeFPlusOne)
		if s.validatorStart != nil {
			s.validatorStart.resumeRoundChange = true
			return true, rowRCFPlusOne
		}
		if !newHeight || !s.opt.Improvements.Has(ResetHeightState) {
			st.broadcastRoundChange(target)
		}
		return true, rowRCFPlusOne
	}
	return st.proposeRoundChange()
}

// proposeRoundChange applies the proposer's existing quorum and justification
// checks. A delayed builder request can use the same checks without inserting
// another round-change message or applying the F+1 rule again.
func (st *step) proposeRoundChange() (bool, int) {
	s := st.s
	r0 := s.cur.view.Round
	if s.rcs.countAt(r0) >= s.quorum() && s.isProposer(s.opt.Self) && s.cur.preprepareSent.Cmp(r0) < 0 {
		st.emitQuorum("ROUND_CHANGE", s.rcs.countAt(r0))
		e := s.rcs.rounds[roundKey(r0)]
		proposal := e.highestBlock
		if s.opt.Improvements.Has(ValidateRoundProposals) && s.roundProposalLive && (proposal == nil || blockHash(proposal) != s.roundProposalHash || s.roundProposalView.Cmp(s.cur.view) != 0) {
			s.roundProposalLive = false
			st.emit(CancelTimers{Kinds: []TimerKind{RoundProposalTimer}})
		}
		if proposal == nil {
			if s.cur.pendingRequest == nil {
				return s.opt.Improvements.Has(ResumeRoundProposals), rowRCNoProposal
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
		if e.highestBlock != nil && s.opt.Improvements.Has(ValidateRoundProposals) {
			hash := blockHash(proposal)
			if s.roundProposalLive && s.roundProposalView.Cmp(s.cur.view) == 0 && s.roundProposalHash == hash {
				return true, rowRCStored
			}
			if s.roundProposalLive {
				s.roundProposalLive = false
				st.emit(CancelTimers{Kinds: []TimerKind{RoundProposalTimer}})
			}
			validate := st.env.ValidateProposal
			if local, ok := st.env.(RoundProposalValidator); ok {
				validate = local.ValidateRoundProposal
			}
			wait, err := validate(proposal)
			if err != nil {
				if errors.Is(err, header.ErrFutureBlock) && st.allowFutureWait(proposal, wait, "local_reproposal") {
					s.gen[RoundProposalTimer]++
					s.roundProposalLive, s.roundProposalView, s.roundProposalHash = true, s.cur.view, hash
					st.emit(ArmTimer{Kind: RoundProposalTimer, View: s.cur.view, Round: s.cur.view.Round, Gen: s.gen[RoundProposalTimer], Duration: wait, Digest: hash})
				}
				return true, rowRCStored
			}
		}
		st.sendPreprepare(proposal, rcs, ps)
		return true, rowRCProposed
	}
	return true, rowRCStored
}
