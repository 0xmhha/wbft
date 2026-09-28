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
// CheckMessage follows checkMessage and isTooFarFutureMessage of
// consensus/wbft/core/backlog.go of go-stablenet (commit 740526d03), which
// are derived from quorum/consensus/istanbul/qbft/core/backlog.go.

package consensus

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

var (
	sequenceThreshold = types.HeightFromUint64(SequenceThreshold)
	roundThreshold    = types.RoundFromUint64(RoundThreshold)
)

// CheckMessage is check_message: it classifies a message with code code and
// view mv against the current view cur, the consensus state st and the prior
// round. All comparisons use the full values of sequences and rounds.
//
// Spec: WBFT-SM-019
func CheckMessage(cur types.View, st StateName, priorRound types.Round, code codec.Code, mv types.View) Class {
	if tooFar(cur, mv) {
		return TooFar
	}
	if code == codec.CodeRoundChange {
		if mv.Sequence.Cmp(cur.Sequence) > 0 {
			return Future
		}
		if mv.Cmp(cur) < 0 {
			return Old
		}
		return Process
	}
	if mv.Cmp(cur) > 0 {
		return Future
	}
	if mv.Cmp(cur) < 0 {
		if d, ok := cur.Sequence.Sub(mv.Sequence); ok && d.CmpUint64(1) == 0 &&
			mv.Round.Cmp(priorRound) == 0 && st == AcceptRequest {
			return ExtraSeal
		}
		return Old
	}
	switch st {
	case AcceptRequest:
		if code > codec.CodePreprepare {
			return Future
		}
		return Process
	case Preprepared:
		if code < codec.CodePrepare {
			return Invalid
		}
		if code > codec.CodePrepare {
			return Future
		}
		return Process
	case Prepared:
		if code == codec.CodePrepare {
			return ExtraSeal
		}
		if code < codec.CodeCommit {
			return Invalid
		}
		return Process
	case Committed:
		if code >= codec.CodePrepare {
			return ExtraSeal
		}
		return Invalid
	}
	return Process
}

// tooFar is the TOO_FAR rule: more than SequenceThreshold sequences ahead, a
// later sequence at a round of RoundThreshold or more, or more than
// RoundThreshold rounds ahead in the current sequence.
func tooFar(cur, mv types.View) bool {
	if mv.Sequence.Cmp(cur.Sequence) > 0 {
		d, _ := mv.Sequence.Sub(cur.Sequence)
		if d.Cmp(sequenceThreshold) > 0 {
			return true
		}
		if mv.Round.Cmp(roundThreshold) >= 0 {
			return true
		}
	}
	if mv.Sequence.Cmp(cur.Sequence) == 0 && mv.Round.Cmp(cur.Round) > 0 {
		if mv.Round.Cmp(cur.Round.AddUint64(RoundThreshold)) > 0 {
			return true
		}
	}
	return false
}
