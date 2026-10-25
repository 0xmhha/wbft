// Copyright 2025 The go-wemix-wbft Authors
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
package epoch

import (
	"math/big"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// committedRuleForHeader resolves activation before classifying the supplied
// number as an epoch or genesis. Only the actual genesis has no parent.
func committedRuleForHeader(chain types.ChainReader, cfg *types.Config, e *types.Header) (bool, error) {
	return ruleForEpochHeader(chain, cfg, e, types.CommittedEpochDiligence)
}

// committedParent follows a hash-bound edge and checks the full height.
func committedParent(chain types.ChainReader, h *types.Header) (*types.Header, error) {
	if h.Number.IsZero() {
		return nil, validator.ErrUnknownAncestor
	}
	p := chain.HeaderByHash(h.ParentHash)
	if p == nil || codec.BlockHash(p) != h.ParentHash || p.Number.AddUint64(1).Cmp(h.Number) != 0 {
		return nil, validator.ErrUnknownAncestor
	}
	return p, nil
}

// committedBoundary finds an actual historical epoch through ancestry. It
// deliberately does not consult canonical-number indexes or truncate heights.
func committedBoundary(chain types.ChainReader, cfg *types.Config, h *types.Header) (*types.Header, *types.EpochInfo, error) {
	for {
		yes, err := validator.IsEpochBlock(cfg, h.Number)
		if err != nil {
			return nil, nil, err
		}
		if yes {
			x, err := codec.DecodeConsensusExtra(h)
			if err != nil {
				return nil, nil, err
			}
			if x.EpochInfo == nil {
				return nil, nil, validator.ErrEpochInfoNil
			}
			return h, x.EpochInfo, nil
		}
		h, err = committedParent(chain, h)
		if err != nil {
			return nil, nil, err
		}
	}
}

type committedObservation struct{ slots, submitted, capacity, credit big.Int }

func committedObservationFor(m map[types.Address]*committedObservation, a types.Address) *committedObservation {
	o := m[a]
	if o == nil {
		o = &committedObservation{}
		m[a] = o
	}
	return o
}

// computeCommittedEpochInfo accounts [L,e-1], where L is the last actual
// epoch in e's ancestry. Its own round and current seals are not observations.
// The successor supplies the hash-bound PrevRound for each historical block,
// including e's PrevRound for its parent. Node-local current seals and rounds
// cannot alter the scores or the epoch information of a prepared re-proposal.
//
// A signing slot belongs to each validator governing the parent of an
// observed block; genesis has no certificates. Each proposer attempt has
// capacity twice that parent's validator count. The final-round proposer
// receives the carried signatures' credit, while parent.Coinbase remains
// the next block's selection anchor. Opportunities use the historical policy.
//
// For D=DiligenceDenominator, W=e-L and r=eligible signing slots, S is
// floor(submitted*D/(2*r)); P is floor(credit*D/capacity), or D with no
// proposer capacity. The next score is
// floor((prior*(10*W-r)+(S+P)*r)/(10*W)). No signing observations carry the
// prior score unchanged. Candidates absent from L receive DefaultDiligence.
func computeCommittedEpochInfo(chain types.ChainReader, cfg *types.Config, e *types.Header, candidates []types.CandidateEntry, stable bool) (*types.EpochInfo, error) {
	parent, err := committedParent(chain, e)
	if err != nil {
		return nil, err
	}
	boundary, latest, err := committedBoundary(chain, cfg, parent)
	if err != nil {
		return nil, err
	}
	span, ok := e.Number.Sub(boundary.Number)
	if !ok || span.IsZero() {
		return nil, ErrZeroEpochDivisor
	}
	prior := latest
	if !boundary.Number.IsZero() {
		p, err := committedParent(chain, boundary)
		if err != nil {
			return nil, err
		}
		_, prior, err = committedBoundary(chain, cfg, p)
		if err != nil {
			return nil, err
		}
	}
	observations := map[types.Address]*committedObservation{}
	// Only two authority records occur in this window: L's and its predecessor.
	// Sets are cached per historical policy, avoiding repeated set construction.
	sets := map[types.ProposerPolicy]*validator.Set{}
	oldSets := map[types.ProposerPolicy]*validator.Set{}
	successor := e
	for h := parent; ; {
		if !h.Number.IsZero() {
			p, err := committedParent(chain, h)
			if err != nil {
				return nil, err
			}
			if !p.Number.IsZero() {
				proposerInfo, parentInfo := latest, latest
				cache := sets
				if h.Number.Cmp(boundary.Number) == 0 {
					proposerInfo = prior
					cache = oldSets
				}
				if p.Number.Cmp(boundary.Number) <= 0 {
					parentInfo = prior
				}
				pol := cfg.ConfigAt(h.Number).ProposerPolicy
				if pol == nil {
					return nil, validator.ErrNoProposerPolicy
				}
				set := cache[*pol]
				if set == nil {
					set, err = validator.NewSetFromEpochInfo(proposerInfo, *pol)
					if err != nil {
						return nil, err
					}
					cache[*pol] = set
				}
				if set.Len() == 0 {
					return nil, ErrProposerNotFound
				}
				x, err := codec.DecodeConsensusExtra(h)
				if err != nil {
					return nil, err
				}
				// uint32 rounds are widened before adding one. Cycles and remainder
				// count all attempts in O(set size), independent of the round magnitude.
				successorExtra, err := codec.DecodeConsensusExtra(successor)
				if err != nil {
					return nil, err
				}
				round := successorExtra.PrevRound
				attempts := uint64(round) + 1
				n := uint64(set.Len())
				cycles, rest := attempts/n, attempts%n
				start := set.CalcProposer(types.ProposerOf(p), 0)
				weight := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(uint64(len(parentInfo.Validators))))
				for i := 0; i < set.Len(); i++ {
					count := cycles
					if uint64(i) < rest {
						count++
					}
					a := set.At((start + i) % set.Len()).Addr
					if a == (types.Address{}) {
						return nil, ErrValidatorNotCandidate
					}
					o := committedObservationFor(observations, a)
					o.capacity.Add(&o.capacity, new(big.Int).Mul(new(big.Int).SetUint64(count), weight))
				}
				winner := set.At(set.CalcProposer(types.ProposerOf(p), uint64(round))).Addr
				for _, index := range parentInfo.Validators {
					a := parentInfo.Candidate(index)
					if a == (types.Address{}) {
						return nil, ErrValidatorNotCandidate
					}
					o := committedObservationFor(observations, a)
					o.slots.Add(&o.slots, big.NewInt(1))
				}
				for _, seal := range []*types.AggregatedSeal{x.PrevPreparedSeal, x.PrevCommittedSeal} {
					signers, err := signerAddresses(parentInfo, seal)
					if err != nil {
						return nil, err
					}
					for _, a := range signers {
						o := committedObservationFor(observations, a)
						o.submitted.Add(&o.submitted, big.NewInt(1))
					}
					o := committedObservationFor(observations, winner)
					o.credit.Add(&o.credit, new(big.Int).SetUint64(uint64(len(signers))))
				}
			}
			if h.Number.Cmp(boundary.Number) == 0 {
				break
			}
			successor, h = h, p
		} else {
			break
		}
	}
	priorScores := map[types.Address]uint64{}
	for _, candidate := range latest.Candidates {
		priorScores[candidate.Addr] = candidate.Diligence
	}
	next := &types.EpochInfo{Candidates: make([]types.Candidate, len(candidates))}
	for i, entry := range candidates {
		d, exists := priorScores[entry.Addr]
		if !exists {
			d = types.DefaultDiligence
		} else {
			o := committedObservationFor(observations, entry.Addr)
			d, err = committedDiligence(d, o, span.Big())
			if err != nil {
				return nil, err
			}
		}
		next.Candidates[i] = types.Candidate{Addr: entry.Addr, Diligence: d}
	}
	return selectNextValidators(e, candidates, next, stable)
}

func committedDiligence(prior uint64, o *committedObservation, span *big.Int) (uint64, error) {
	D := new(big.Int).SetUint64(types.DiligenceDenominator)
	if prior > 2*types.DiligenceDenominator {
		return 0, ErrDiligenceRange
	}
	if span.Sign() <= 0 {
		return 0, ErrZeroEpochDivisor
	}
	if o.slots.Sign() < 0 || o.slots.Cmp(span) > 0 || o.submitted.Sign() < 0 || o.capacity.Sign() < 0 || o.credit.Sign() < 0 {
		return 0, ErrSealCountRange
	}
	maxSubmitted := new(big.Int).Mul(big.NewInt(2), &o.slots)
	if o.submitted.Cmp(maxSubmitted) > 0 || o.credit.Cmp(&o.capacity) > 0 {
		return 0, ErrSealCountRange
	}
	if o.slots.Sign() == 0 {
		return prior, nil
	}
	s := new(big.Int).Mul(&o.submitted, D)
	s.Quo(s, maxSubmitted)
	p := new(big.Int).Set(D)
	if o.capacity.Sign() > 0 {
		p.Mul(&o.credit, D)
		p.Quo(p, &o.capacity)
	}
	denominator := new(big.Int).Mul(big.NewInt(10), span)
	oldWeight := new(big.Int).Sub(denominator, &o.slots)
	score := new(big.Int).Mul(new(big.Int).SetUint64(prior), oldWeight)
	observed := new(big.Int).Add(s, p)
	observed.Mul(observed, &o.slots)
	score.Add(score, observed)
	score.Quo(score, denominator)
	if !score.IsUint64() || score.Uint64() > 2*types.DiligenceDenominator {
		return 0, ErrDiligenceRange
	}
	return score.Uint64(), nil
}
