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
// The receive path follows handleEncodedMsg, verifySignatures,
// handleDecodedMessage and checkValidatorSignature of consensus/wbft/core of
// go-stablenet (commit 740526d03), which are derived from
// quorum/consensus/istanbul/qbft/core/handler.go.

package consensus

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// Rows of the message-handling outcome table (A-05 section 16).
const (
	rowUndecodable      = 1
	rowBadSignature     = 2
	rowTooFar           = 3
	rowOld              = 4
	rowInvalid          = 5
	rowBacklogged       = 6
	rowBacklogDropped   = 7
	rowExtraNoTarget    = 8
	rowExtraInvalid     = 9
	rowExtraStored      = 10
	rowExtraNotNewer    = 11
	rowExtraOtherCode   = 12
	rowPreprepareReject = 13
	rowPreprepareFuture = 14
	rowPreprepareAccept = 15
	rowPrepareInvalid   = 16
	rowPrepareStored    = 17
	rowPrepareQuorum    = 18
	rowCommitInvalid    = 19
	rowCommitStored     = 20
	rowCommitDecided    = 21
	rowCommitFinalFail  = 22
	rowRCOtherSequence  = 23
	rowRCStored         = 24
	rowRCFPlusOne       = 25
	rowRCProposed       = 26
	rowRCNotJustified   = 27
	rowRCNoProposal     = 28
)

// Via values of Outcome.
const (
	viaDirect  = "direct"
	viaBacklog = "backlog"
)

// isConsensusCode reports whether code is one of the four message codes.
func isConsensusCode(code codec.Code) bool {
	return code >= codec.CodePreprepare && code <= codec.CodeRoundChange
}

// signatureValidatorSet is signature_validator_set(node, v): the prior set for
// a message of the previous sequence at the prior round while in
// AcceptRequest, and the current set otherwise.
//
// Spec: WBFT-SM-016
func (s *State) signatureValidatorSet(v types.View) *validator.Set {
	cur := s.cur.view
	if v.Cmp(cur) < 0 && s.state == AcceptRequest && s.prior.validators != nil {
		if prev, ok := cur.Sequence.Sub(types.HeightFromUint64(1)); ok &&
			v.Cmp(types.View{Sequence: prev, Round: s.prior.round}) == 0 {
			return s.prior.validators
		}
	}
	return s.validators
}

// onMessage handles a received message: code, decoding and signatures, then
// handle_decoded. A message whose processing returns OK is relayed with the
// received bytes.
//
// Spec: WBFT-SM-011, WBFT-SM-013, WBFT-SM-015, WBFT-SM-016, WBFT-SM-017, WBFT-SM-020
func (st *step) onMessage(in Message) {
	s := st.s
	o := Outcome{Code: in.Code, Via: viaDirect, Peer: in.Peer, DedupKey: codec.DedupKey(in.Payload)}
	if in.Peer == s.opt.Self && s.opt.Self != (types.Address{}) {
		o.Via = "self"
	}
	if !isConsensusCode(in.Code) {
		o.Row = rowUndecodable
		st.emit(o)
		return
	}
	isMember := func(a types.Address, v types.View) bool { return s.signatureValidatorSet(v).Contains(a) }
	m, err := codec.DecodeMessage(in.Code, in.Payload)
	if err != nil {
		o.Row = rowUndecodable
		st.emit(o)
		return
	}
	o.View = m.View
	v, err := RecoverDecoded(m, isMember)
	if err != nil {
		o.Row = rowBadSignature
		st.emit(o)
		return
	}
	o.Source = v.Source
	ok, cls, row := st.handleDecoded(v)
	o.Check, o.Row, o.Relayed = cls, row, ok
	if ok {
		st.emit(Relay{Code: in.Code, Payload: in.Payload, Validators: s.validators})
	}
	st.emit(o)
}

// onReplay handles a backlog replay or a deferred PRE-PREPARE. Its signatures
// are not verified again; a message whose processing returns OK is relayed
// with its re-encoding.
//
// Spec: WBFT-SM-012, WBFT-SM-074
func (st *step) onReplay(v *Verified) {
	if v == nil || v.Msg == nil {
		return
	}
	s := st.s
	payload, err := v.Encode()
	o := Outcome{Code: v.Msg.Code, Source: v.Source, View: v.Msg.View, Via: viaBacklog, DedupKey: codec.DedupKey(payload)}
	ok, cls, row := st.handleDecoded(v)
	o.Check, o.Row = cls, row
	if ok && err == nil {
		o.Relayed = true
		st.emit(Relay{Code: v.Msg.Code, Payload: payload, Validators: s.validators})
	}
	st.emit(o)
}

// handleDecoded is handle_decoded: check_message, then the backlog, the extra
// seals or the handler of the code. It returns whether the result is OK, the
// class and the outcome row.
//
// Spec: WBFT-SM-019, WBFT-SM-020
func (st *step) handleDecoded(v *Verified) (bool, Class, int) {
	s := st.s
	cls := CheckMessage(s.cur.view, s.state, s.prior.round, v.Msg.Code, v.Msg.View)
	switch cls {
	case Future:
		return false, cls, st.addToBacklog(v)
	case ExtraSeal:
		ok, row := st.addExtraSeal(v)
		return ok, cls, row
	case TooFar:
		return false, cls, rowTooFar
	case Old:
		return false, cls, rowOld
	case Invalid:
		return false, cls, rowInvalid
	}
	var ok bool
	var row int
	switch v.Msg.Code {
	case codec.CodePreprepare:
		ok, row = st.handlePreprepare(v)
	case codec.CodePrepare:
		ok, row = st.handlePrepare(v)
	case codec.CodeCommit:
		ok, row = st.handleCommit(v)
	case codec.CodeRoundChange:
		ok, row = st.handleRoundChange(v)
	}
	return ok, cls, row
}
