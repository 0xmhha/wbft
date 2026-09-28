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
// The handlers of this file follow preprepare.go, prepare.go, commit.go and
// core.go (verifySeal) of consensus/wbft/core of go-stablenet (commit
// 740526d03), which are derived from quorum/consensus/istanbul/qbft/core.

package consensus

import (
	"bytes"
	"errors"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// broadcast emits m unless the node is not a member of the current set, in
// which case nothing is sent and false is returned.
//
// Spec: WBFT-SM-003
func (st *step) broadcast(m *codec.Message, sealData []byte) bool {
	s := st.s
	if s.validators == nil || !s.validators.Contains(s.opt.Self) {
		return false
	}
	st.emit(Broadcast{Msg: m, SealData: sealData, Validators: s.validators})
	return true
}

// sortByEncoding orders justification members by the bytes of their
// encoding; the protocol leaves the order open, and a fixed order keeps the
// outputs deterministic.
func sortByEncoding(ms []*codec.Message, enc func(*codec.Message) ([]byte, error)) []*codec.Message {
	type item struct {
		m *codec.Message
		b []byte
	}
	items := make([]item, len(ms))
	for i, m := range ms {
		b, _ := enc(m)
		items[i] = item{m, b}
	}
	slices.SortStableFunc(items, func(a, b item) int { return bytes.Compare(a.b, b.b) })
	out := make([]*codec.Message, len(items))
	for i, it := range items {
		out[i] = it.m
	}
	return out
}

func messagesOf(vs []*Verified) []*codec.Message {
	out := make([]*codec.Message, len(vs))
	for i, v := range vs {
		out[i] = v.Msg
	}
	return out
}

// sendPreprepare is send_preprepare: only for a proposal of the current
// sequence and only by the proposer. The justification is the signed
// payloads of rcs and the PREPAREs ps.
//
// Spec: WBFT-SM-034, WBFT-SM-035, WBFT-SM-036
func (st *step) sendPreprepare(p *types.Block, rcs, ps []*Verified) {
	s := st.s
	v := s.cur.view
	if p.Header.Number.Cmp(v.Sequence) != 0 || !s.isProposer(s.opt.Self) {
		return
	}
	m := &codec.Message{
		Code:         codec.CodePreprepare,
		View:         v,
		Proposal:     p,
		RoundChanges: sortByEncoding(messagesOf(rcs), codec.EncodeSignedRoundChange),
		Prepares:     sortByEncoding(messagesOf(ps), codec.EncodeMessage),
	}
	if st.broadcast(m, nil) {
		s.cur.preprepareSent = v.Round
		s.cur.preprepareSentValid = true
	}
}

// handlePreprepare checks a PRE-PREPARE of the current view in the order of
// WBFT-SM-037 and accepts it: restart the round timer, store it, move to
// Preprepared and send PREPARE. A proposal from the future arms the future
// timer instead.
//
// Spec: WBFT-SM-037, WBFT-SM-038, WBFT-SM-039, WBFT-SM-062
func (st *step) handlePreprepare(v *Verified) (bool, int) {
	s := st.s
	m := v.Msg
	if m.Proposal == nil || m.Proposal.Header == nil {
		return false, rowPreprepareReject
	}
	if !s.isProposer(v.Source) {
		return false, rowPreprepareReject
	}
	if m.View.Sequence.RefLow64() != m.Proposal.Header.Number.RefLow64() { //wbft:low64 HH-01
		return false, rowPreprepareReject
	}
	if m.View.Round.RefLow64() > 0 { //wbft:low64 HH-70
		if !IsJustified(blockHash(m.Proposal), m.View, summarizeRoundChanges(v.roundChanges()), summarizePrepares(v.prepares()), s.quorum()) {
			return false, rowPreprepareReject
		}
	}
	future, err := st.env.ValidateProposal(m.Proposal)
	if err != nil {
		if errors.Is(err, header.ErrFutureBlock) {
			st.armFutureTimer(v, future)
			return false, rowPreprepareFuture
		}
		return false, rowPreprepareReject
	}
	if s.state == AcceptRequest {
		st.startRoundTimer()
		s.cur.preprepare = v
		st.emit(Event{Record: event.Record{
			Kind: event.PreprepareAccept,
			View: event.ViewOf(s.cur.view),
			Fields: map[string]any{
				"digest":     hexHash(blockHash(m.Proposal)),
				"proposer":   hexAddr(v.Source),
				"block_time": m.Proposal.Header.Time,
			},
		}})
		st.setState(Preprepared)
		st.broadcastVote(codec.CodePrepare)
	}
	return true, rowPreprepareAccept
}

// broadcastVote sends the PREPARE or COMMIT of the current view for the
// accepted proposal, with seal_data(header, uint32(round), type) for the
// runner to seal.
//
// Spec: WBFT-SM-040, WBFT-SM-044
func (st *step) broadcastVote(code codec.Code) {
	s := st.s
	p := s.cur.preprepare.Msg.Proposal
	t := types.PrepareSeal
	if code == codec.CodeCommit {
		t = types.CommitSeal
	}
	m := &codec.Message{Code: code, View: s.cur.view, Digest: blockHash(p)}
	st.broadcast(m, codec.SealData(p.Header, s.cur.view.Round.RefLow32(), t)) //wbft:low64 HH-74
}

// verifySeal checks that sealer is a member of vs and that seal is its BLS
// signature over seal_data(h, round, t). Membership is checked before the
// signature.
//
// Spec: WBFT-CRYPTO-043
func verifySeal(vs *validator.Set, h *types.Header, round uint32, t types.SealType, seal []byte, sealer types.Address) bool {
	if vs == nil {
		return false
	}
	i, ok := vs.IndexOf(sealer)
	if !ok {
		return false
	}
	pk, err := bls.DecodePublicKey(vs.At(i).BLSPublicKey)
	if err != nil {
		return false
	}
	sig, err := bls.DecodeSignature(seal)
	if err != nil {
		return false
	}
	return bls.Verify(pk, codec.SealData(h, round, t), sig)
}

// checkVote checks the digest and the seal of a PREPARE or COMMIT against
// block with the set vs.
func checkVote(vs *validator.Set, block *types.Block, v *Verified) bool {
	m := v.Msg
	if m.Digest != blockHash(block) {
		return false
	}
	t := types.PrepareSeal
	if m.Code == codec.CodeCommit {
		t = types.CommitSeal
	}
	return verifySeal(vs, block.Header, m.View.Round.RefLow32(), t, m.Seal, v.Source) //wbft:low64 HH-74
}

// handlePrepare stores a PREPARE of the current view and, at the quorum,
// locks, keeps the certificate, moves to Prepared and sends COMMIT.
//
// Spec: WBFT-SM-041, WBFT-SM-042, WBFT-SM-043
func (st *step) handlePrepare(v *Verified) (bool, int) {
	s := st.s
	p := s.cur.preprepare.Msg.Proposal
	if !checkVote(s.validators, s.cur.preprepare.Msg.Proposal, v) {
		return false, rowPrepareInvalid
	}
	s.cur.prepares[v.Source] = v
	if len(s.cur.prepares) >= s.quorum() && s.state < Prepared {
		r := s.cur.view.Round
		s.cur.preparedRound = &r
		cert := make([]*Verified, 0, len(s.cur.prepares))
		for _, a := range sortedAddrs(s.cur.prepares) {
			x := s.cur.prepares[a]
			c := *x.Msg
			cert = append(cert, &Verified{Msg: &c, Source: x.Source})
		}
		s.certificate = cert
		s.cur.preparedBlock = p
		st.emitQuorum("PREPARE", len(s.cur.prepares))
		st.setState(Prepared)
		st.broadcastVote(codec.CodeCommit)
		return true, rowPrepareQuorum
	}
	return true, rowPrepareStored
}

// handleCommit stores a COMMIT of the current view and decides at the
// quorum.
//
// Spec: WBFT-SM-045, WBFT-SM-046
func (st *step) handleCommit(v *Verified) (bool, int) {
	s := st.s
	if !checkVote(s.validators, s.cur.preprepare.Msg.Proposal, v) {
		return false, rowCommitInvalid
	}
	s.cur.commits[v.Source] = v
	if len(s.cur.commits) >= s.quorum() {
		st.emitQuorum("COMMIT", len(s.cur.commits))
		if st.decide() {
			return true, rowCommitDecided
		}
		return true, rowCommitFinalFail
	}
	return true, rowCommitStored
}

func (st *step) emitQuorum(what string, count int) {
	st.emit(Event{Record: event.Record{
		Kind:   event.Quorum,
		View:   event.ViewOf(st.s.cur.view),
		Fields: map[string]any{"what": what, "count": count, "quorum": st.s.quorum()},
	}})
}

// decide moves to Committed, builds the seal lists from the stored PREPAREs
// and COMMITs and finalizes. A failed finalize sends ROUND-CHANGE for the next
// round without leaving the view; the round timer keeps running.
//
// Spec: WBFT-SM-047, WBFT-SM-048, WBFT-SM-049, WBFT-SM-050
func (st *step) decide() bool {
	s := st.s
	st.setState(Committed)
	p := s.cur.preprepare.Msg.Proposal
	seals := func(msgs map[types.Address]*Verified) []types.SealEntry {
		out := make([]types.SealEntry, 0, len(msgs))
		for _, a := range sortedAddrs(msgs) {
			i, ok := s.validators.IndexOf(a)
			if !ok {
				continue
			}
			out = append(out, types.SealEntry{Sealer: uint32(i), Seal: append([]byte(nil), msgs[a].Msg.Seal...)})
		}
		return out
	}
	blk, err := st.env.CommitHeader(p, s.cur.view.Round, s.validators, seals(s.cur.prepares), seals(s.cur.commits))
	if err != nil {
		st.broadcastRoundChange(s.cur.view.Round.AddUint64(1))
		return false
	}
	st.emit(Commit{Block: blk, Round: s.cur.view.Round})
	return true
}
