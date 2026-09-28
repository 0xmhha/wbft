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
// IsJustified and its helpers follow consensus/wbft/core/justification.go of
// go-stablenet (commit 740526d03), which is derived from
// quorum/consensus/istanbul/qbft/core/justification.go.

package consensus

import "github.com/0xmhha/wbft/types"

// RoundChangeSummary is the signed payload of a ROUND-CHANGE as the
// justification rules read it. PreparedRound is nil when the payload has no
// prepared pair.
type RoundChangeSummary struct {
	Source         types.Address
	View           types.View
	PreparedRound  *types.Round
	PreparedDigest types.Hash
}

// PrepareSummary is a PREPARE as the justification rules read it.
type PrepareSummary struct {
	Source types.Address
	View   types.View
	Digest types.Hash
}

// IsJustified is is_justified: whether the ROUND-CHANGE payloads rcs and the
// PREPAREs prepares justify proposing the block with hash proposal in view
// target with quorum size quorum. The steps run in the reference order:
// deduplication by source (first wins), a quorum of ROUND-CHANGEs, every
// ROUND-CHANGE for target, no PREPAREs or a quorum of them, one round and the
// proposal's digest for all PREPAREs, then the rule for no PREPAREs or for a
// prepared round.
//
// Spec: WBFT-SM-061
func IsJustified(proposal types.Hash, target types.View, rcs []RoundChangeSummary, prepares []PrepareSummary, quorum int) bool {
	rcs = dedupRoundChanges(rcs)
	ps := dedupPrepares(prepares)
	if len(rcs) < quorum {
		return false
	}
	for _, rc := range rcs {
		if rc.View.Sequence.Cmp(target.Sequence) != 0 || rc.View.Round.Cmp(target.Round) != 0 {
			return false
		}
	}
	if len(ps) != 0 && len(ps) < quorum {
		return false
	}
	var preparedRound *types.Round
	if len(ps) > 0 {
		r := ps[0].View.Round
		preparedRound = &r
		for _, p := range ps {
			if p.View.Round.Cmp(*preparedRound) != 0 {
				return false
			}
			if p.Digest != proposal {
				return false
			}
		}
	}
	if preparedRound == nil {
		nilCount := 0
		for _, rc := range rcs {
			if (rc.PreparedRound == nil || rc.PreparedRound.IsZero()) && rc.PreparedDigest == (types.Hash{}) {
				nilCount++
				if nilCount == quorum {
					return true
				}
			}
		}
		return false
	}
	lowerOrEqual := 0
	hasMatch := false
	for _, rc := range rcs {
		if rc.PreparedRound == nil || rc.PreparedRound.Cmp(*preparedRound) <= 0 {
			lowerOrEqual++
			if rc.PreparedRound != nil && rc.PreparedRound.Cmp(*preparedRound) == 0 && rc.PreparedDigest == proposal {
				hasMatch = true
			}
			if lowerOrEqual >= quorum && hasMatch {
				return true
			}
		}
	}
	return false
}

// hasMatchingRoundChangeAndPrepares reports whether the PREPAREs, deduplicated
// by source, are at least a quorum and all carry the prepared round and
// digest of the ROUND-CHANGE. The sequence of the PREPAREs is not checked.
//
// Spec: WBFT-SM-056
func hasMatchingRoundChangeAndPrepares(rc RoundChangeSummary, prepares []PrepareSummary, quorum int) bool {
	ps := dedupPrepares(prepares)
	if len(ps) < quorum {
		return false
	}
	for _, p := range ps {
		if p.Digest != rc.PreparedDigest {
			return false
		}
		if rc.PreparedRound == nil || p.View.Round.Cmp(*rc.PreparedRound) != 0 {
			return false
		}
	}
	return true
}

func dedupRoundChanges(in []RoundChangeSummary) []RoundChangeSummary {
	out := make([]RoundChangeSummary, 0, len(in))
	for _, m := range in {
		if !containsSource(out, m.Source, func(x RoundChangeSummary) types.Address { return x.Source }) {
			out = append(out, m)
		}
	}
	return out
}

func dedupPrepares(in []PrepareSummary) []PrepareSummary {
	out := make([]PrepareSummary, 0, len(in))
	for _, m := range in {
		if !containsSource(out, m.Source, func(x PrepareSummary) types.Address { return x.Source }) {
			out = append(out, m)
		}
	}
	return out
}

func containsSource[T any](xs []T, a types.Address, src func(T) types.Address) bool {
	for _, x := range xs {
		if src(x) == a {
			return true
		}
	}
	return false
}

// summarizeRoundChange returns the justification view of a ROUND-CHANGE.
func summarizeRoundChange(v *Verified) RoundChangeSummary {
	return RoundChangeSummary{
		Source:         v.Source,
		View:           v.Msg.View,
		PreparedRound:  v.Msg.PreparedRound,
		PreparedDigest: v.Msg.PreparedDigest,
	}
}

func summarizePrepares(ps []*Verified) []PrepareSummary {
	out := make([]PrepareSummary, len(ps))
	for i, p := range ps {
		out[i] = PrepareSummary{Source: p.Source, View: p.Msg.View, Digest: p.Msg.Digest}
	}
	return out
}

func summarizeRoundChanges(rcs []*Verified) []RoundChangeSummary {
	out := make([]RoundChangeSummary, len(rcs))
	for i, rc := range rcs {
		out[i] = summarizeRoundChange(rc)
	}
	return out
}
