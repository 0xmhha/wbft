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
//
// The next-epoch computation follows buildEpochInfo, decideValidators,
// sortCandidates, getSignerAddress, verifyEpoch and computeShuffledIndex of
// consensus/wbft/engine/engine.go of go-stablenet (commit 740526d03), and
// CreateInitialEpochInfo of consensus/wbft/config.go. computeShuffledIndex
// there is derived from the Prysm implementation of the Ethereum
// consensus-layer shuffle.

package epoch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/refsort"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// Errors of the next-epoch computation. The texts follow the reference.
var (
	ErrEmptySeals         = errors.New("empty seals")
	ErrZeroSignerAddress  = errors.New("validator address is zero")
	ErrProposerNotFound   = errors.New("failed to find valid proposer")
	ErrSealCountRange     = errors.New("seal count exceed the range for non validator in prior epoch")
	ErrDiligenceRange     = errors.New("WBFT: Invalid Diligence exceeds maximum")
	ErrSealerIndexRange   = errors.New("epoch: sealer index outside the validators of the epoch info")
	ErrZeroEpochDivisor   = errors.New("epoch: division by zero in the diligence computation")
	ErrEpochInfoMismatch  = errors.New("WBFT: epoch info mismatch")
	ErrShuffleOutOfBounds = errors.New("input index out of bounds")

	ErrValidatorNotCandidate = errors.New("epoch: validator of the epoch info is not a candidate")
)

// ScoredCandidate is a candidate as sorted for validator selection: every
// candidate has power 1 in StableNet, so the order is by diligence.
type ScoredCandidate struct {
	Addr      types.Address
	Power     uint64
	Diligence uint64
}

// SortCandidates returns the candidate indices ordered by power descending,
// then diligence descending. Candidates that compare equal are ordered as the
// reference implementation orders them (internal/refsort).
//
// Spec: WBFT-EPOCH-016
func SortCandidates(cs []ScoredCandidate) []int {
	idx := make([]int, len(cs))
	for i := range idx {
		idx[i] = i
	}
	refsort.Slice(idx, func(i, j int) bool {
		a, b := cs[idx[i]], cs[idx[j]]
		if a.Power != b.Power {
			return a.Power > b.Power
		}
		return a.Diligence > b.Diligence
	})
	return idx
}

// ShuffleRoundCount is the number of rounds of the swap-or-not shuffle.
const ShuffleRoundCount = 33

// ComputeShuffledIndex is compute_shuffled_index(index, count, seed): the
// swap-or-not shuffle of the Ethereum consensus layer with keccak256 instead
// of SHA-256 and 33 rounds.
//
// Spec: WBFT-EPOCH-018
func ComputeShuffledIndex(index, count uint64, seed types.Hash) (uint64, error) {
	if index >= count {
		return 0, fmt.Errorf("%w: input index %d out of bounds: %d", ErrShuffleOutOfBounds, index, count)
	}
	const pivotViewSize = 32 + 1
	buf := make([]byte, 32+1+4)
	posBuffer := make([]byte, 8)
	copy(buf[:32], seed[:])
	for round := uint8(0); round < ShuffleRoundCount; round++ {
		buf[32] = round
		h := keccak.Sum256(buf[:pivotViewSize])
		pivot := binary.LittleEndian.Uint64(h[:8]) % count
		flip := (pivot + count - index) % count
		position := index
		if flip > position {
			position = flip
		}
		binary.LittleEndian.PutUint64(posBuffer, position>>8)
		copy(buf[pivotViewSize:], posBuffer[:4])
		source := keccak.Sum256(buf)
		byteV := source[(position&0xff)>>3]
		bitV := (byteV >> (position & 0x7)) & 0x1
		if bitV == 1 {
			index = flip
		}
	}
	return index, nil
}

// Shuffle returns ComputeShuffledIndex(i, n, seed) for i = 0 .. n-1.
func Shuffle(n int, seed types.Hash) []int {
	out := make([]int, n)
	for i := range out {
		j, _ := ComputeShuffledIndex(uint64(i), uint64(n), seed) // i < n
		out[i] = int(j)
	}
	return out
}

// InitialEpochInfo is the genesis EpochInfo: one candidate per genesis
// validator in order with the default diligence, validators 0 .. k-1 and the
// genesis BLS keys.
//
// Spec: WBFT-EPOCH-023, WBFT-EPOCH-024
func InitialEpochInfo(init types.GenesisInit) (*types.EpochInfo, error) {
	if len(init.BLSPublicKeys) < len(init.Validators) {
		return nil, validator.ErrKeysShort
	}
	ei := &types.EpochInfo{}
	for i, a := range init.Validators {
		ei.Candidates = append(ei.Candidates, types.Candidate{Addr: a, Diligence: types.DefaultDiligence})
		ei.Validators = append(ei.Validators, uint32(i))
		ei.BLSPublicKeys = append(ei.BLSPublicKeys, append([]byte(nil), init.BLSPublicKeys[i]...))
	}
	return ei, nil
}

// GenesisExtra is the Extra of the genesis header built from the chain
// configuration: vanity and randao reveal empty, rounds 0, seals absent,
// gas tip gasTip (INITIAL_GAS_TIP when nil) and the initial EpochInfo of
// init. A negative gas tip fails the encoding as in the reference.
//
// Spec: WBFT-ENC-060, WBFT-EPOCH-023
func GenesisExtra(init types.GenesisInit, gasTip *big.Int) ([]byte, error) {
	ei, err := InitialEpochInfo(init)
	if err != nil {
		return nil, err
	}
	tip := new(big.Int).SetUint64(types.InitialGasTip)
	if gasTip != nil {
		tip.Set(gasTip)
	}
	return codec.EncodeExtra(&types.WBFTExtra{GasTip: tip, EpochInfo: ei})
}

// signerAddresses resolves the sealer indices of an aggregated seal with an
// EpochInfo, in ascending bit order.
func signerAddresses(ei *types.EpochInfo, seal *types.AggregatedSeal) ([]types.Address, error) {
	if seal == nil {
		return nil, ErrEmptySeals
	}
	sealers := seal.Sealers.Sealers()
	out := make([]types.Address, len(sealers))
	for i, idx := range sealers {
		if int(idx) >= len(ei.Validators) {
			return nil, ErrSealerIndexRange
		}
		a := ei.Candidate(ei.Validators[idx])
		if a == (types.Address{}) {
			return nil, ErrZeroSignerAddress
		}
		out[i] = a
	}
	return out, nil
}

type candidateInfo struct {
	isValidator  bool // in the current epoch
	wasValidator bool // in the prior epoch
	candidate    types.Candidate
}

// ComputeNextEpochInfo is compute_next_epoch_info(chain, e, candidates): the
// EpochInfo that epoch block e records for the next epoch. e is the epoch
// header (its EpochInfo is not read); its MixDigest is the shuffle seed.
// candidates is the candidate list of the state after executing e, each with
// its BLS key (empty when none). It returns nil for a block that is not an
// epoch block.
//
// Spec: WBFT-EPOCH-008, WBFT-EPOCH-009, WBFT-EPOCH-010, WBFT-EPOCH-011, WBFT-EPOCH-013, WBFT-EPOCH-019, WBFT-EPOCH-020
func ComputeNextEpochInfo(chain types.ChainReader, cfg *types.Config, e *types.Header, candidates []types.CandidateEntry) (*types.EpochInfo, error) {
	isEpoch, err := validator.IsEpochBlock(cfg, e.Number)
	if err != nil {
		return nil, err
	}
	if !isEpoch {
		return nil, nil
	}
	if e.Number.IsZero() {
		return InitialEpochInfo(cfg.Init)
	}

	proposed := map[types.Address]uint64{}
	submitted := map[types.Address]uint64{}
	beingProposer := map[types.Address]int64{}
	var proposers []types.Address
	var epochLength uint64
	var firstProposer, lastProposer types.Address

	latestEpoch, latest, err := validator.GoverningEpochInfo(chain, cfg, e, nil)
	if err != nil {
		return nil, err
	}

	validatorsDiff := 0 // len(latest.Validators) - len(prior set); may be negative
	it := e
	for latestEpoch.Cmp(it.Number) != 0 {
		extra, err := codec.DecodeExtra(it)
		if err != nil {
			return nil, err
		}
		proposer := it.Coinbase
		proposers = append(proposers, proposer)

		parent := chain.Header(it.ParentHash, it.Number.RefLow64()-1) //wbft:low64 HH-54
		if parent == nil {
			return nil, validator.ErrUnknownAncestor
		}
		info := latest
		if latestEpoch.Cmp(parent.Number) == 0 {
			_, pinfo, err := validator.GoverningEpochInfo(chain, cfg, parent, nil)
			if err != nil {
				return nil, err
			}
			firstProposer = it.Coinbase
			lastProposer = parent.Coinbase
			info = pinfo
			validatorsDiff = len(latest.Validators) - len(pinfo.Validators)
		}

		if parent.Number.IsZero() {
			// Block 1 carries no previous-block seals.
			beingProposer[proposer]--
		} else {
			prepareSigners, err := signerAddresses(info, extra.PrevPreparedSeal)
			if err != nil {
				return nil, err
			}
			proposed[proposer] += uint64(len(prepareSigners))
			for _, a := range prepareSigners {
				submitted[a]++
			}
			commitSigners, err := signerAddresses(info, extra.PrevCommittedSeal)
			if err != nil {
				return nil, err
			}
			proposed[proposer] += uint64(len(commitSigners))
			for _, a := range commitSigners {
				submitted[a]++
			}
		}
		it = parent
		epochLength++
	}

	candidateMap := map[types.Address]*candidateInfo{}
	var current []types.Address
	for _, c := range latest.Candidates {
		candidateMap[c.Addr] = &candidateInfo{candidate: c}
	}
	for _, v := range latest.Validators {
		a := latest.Candidate(v)
		ci := candidateMap[a]
		if ci == nil {
			// A validator index outside the candidates resolves to the zero
			// address, which is not a candidate.
			return nil, ErrValidatorNotCandidate
		}
		ci.isValidator = true
		current = append(current, a)
	}

	if !it.Number.IsZero() {
		parent := chain.Header(it.ParentHash, it.Number.RefLow64()-1) //wbft:low64 HH-54
		if parent == nil {
			return nil, validator.ErrUnknownAncestor
		}
		_, prior, err := validator.GoverningEpochInfo(chain, cfg, parent, nil)
		if err != nil {
			return nil, err
		}
		for _, v := range prior.Validators {
			if ci := candidateMap[prior.Candidate(v)]; ci != nil {
				ci.wasValidator = true
			}
		}
	}

	// Replay proposer opportunities, oldest block first.
	pol := cfg.ConfigAt(e.Number).ProposerPolicy
	if pol == nil {
		return nil, validator.ErrNoProposerPolicy
	}
	valSet, err := validator.NewSet(current, latest.BLSPublicKeys, *pol)
	if err != nil {
		return nil, err
	}
	for i := len(proposers) - 1; i >= 0; i-- {
		proposer := proposers[i]
		for round := 0; ; round++ {
			if round >= len(current) {
				return nil, ErrProposerNotFound
			}
			p := valSet.At(valSet.CalcProposer(lastProposer, uint64(round))).Addr
			beingProposer[p]++
			if p == proposer {
				break
			}
		}
		lastProposer = proposer
	}

	next := &types.EpochInfo{Candidates: make([]types.Candidate, len(candidates))}
	for i, entry := range candidates {
		addr := entry.Addr
		var d uint64
		ci := candidateMap[addr]
		if ci == nil {
			d = types.DefaultDiligence
		} else {
			D := types.DiligenceDenominator
			s := submitted[addr]
			rate := epochLength
			if epochLength == 0 {
				return nil, ErrZeroEpochDivisor
			}
			d = s * D / (2 * epochLength)
			if !ci.isValidator {
				rate = 1
				d = s * D / 2
			} else if !ci.wasValidator {
				rate = epochLength - 1
				if s > 2*(epochLength-1) {
					return nil, ErrSealCountRange
				}
				if epochLength-1 == 0 {
					return nil, ErrZeroEpochDivisor
				}
				d = s * D / (2 * (epochLength - 1))
			}
			if w := beingProposer[addr]; w > 0 {
				maxProposed := 2 * len(latest.Validators) * int(w)
				if addr == firstProposer && ci.wasValidator {
					maxProposed -= 2 * validatorsDiff
				}
				if maxProposed == 0 {
					return nil, ErrZeroEpochDivisor
				}
				d += proposed[addr] * D / uint64(maxProposed)
			} else {
				d += D
			}
			d = (ci.candidate.Diligence*(10*epochLength-rate) + d*rate) / 10 / epochLength
		}
		if d > 2*types.DiligenceDenominator {
			return nil, fmt.Errorf("%w: %d", ErrDiligenceRange, d)
		}
		next.Candidates[i] = types.Candidate{Addr: addr, Diligence: d}
	}

	scored := make([]ScoredCandidate, len(next.Candidates))
	for i, c := range next.Candidates {
		scored[i] = ScoredCandidate{Addr: c.Addr, Power: 1, Diligence: c.Diligence}
	}
	order := SortCandidates(scored)
	next.Validators = make([]uint32, 0)
	next.BLSPublicKeys = make([][]byte, 0)
	n := uint64(len(order))
	for i := uint64(0); i < n; i++ {
		j, err := ComputeShuffledIndex(i, n, e.MixDigest)
		if err != nil {
			return nil, err
		}
		idx := order[j]
		key := candidates[idx].BLSPublicKey
		if len(key) == 0 {
			// Kept as a candidate, not a validator.
			continue
		}
		next.Validators = append(next.Validators, uint32(idx))
		next.BLSPublicKeys = append(next.BLSPublicKeys, append([]byte(nil), key...))
	}
	return next, nil
}

// VerifyEpochInfo recomputes the EpochInfo of epoch block e and compares it
// with the one e carries: the candidate count, then address and diligence of
// each candidate, the validator count and indices, the key count and bytes.
// Any error of the recomputation is returned.
//
// Spec: WBFT-EPOCH-021, WBFT-HDR-131, WBFT-HDR-132
func VerifyEpochInfo(chain types.ChainReader, cfg *types.Config, e *types.Header, candidates []types.CandidateEntry) error {
	want, err := ComputeNextEpochInfo(chain, cfg, e.Copy(), candidates)
	if err != nil {
		return err
	}
	x, err := codec.DecodeExtra(e)
	if err != nil {
		return err
	}
	got := x.EpochInfo
	if got == nil {
		return validator.ErrEpochInfoNil
	}
	if want == nil {
		want = &types.EpochInfo{}
	}
	if len(want.Candidates) != len(got.Candidates) {
		return fmt.Errorf("%w: candidate count", ErrEpochInfoMismatch)
	}
	for i := range want.Candidates {
		if want.Candidates[i].Addr != got.Candidates[i].Addr {
			return fmt.Errorf("%w: candidate %d address", ErrEpochInfoMismatch, i)
		}
		if want.Candidates[i].Diligence != got.Candidates[i].Diligence {
			return fmt.Errorf("%w: candidate %d diligence", ErrEpochInfoMismatch, i)
		}
	}
	if len(want.Validators) != len(got.Validators) {
		return fmt.Errorf("%w: validator count", ErrEpochInfoMismatch)
	}
	for i := range got.Validators {
		if want.Validators[i] != got.Validators[i] {
			return fmt.Errorf("%w: validator %d", ErrEpochInfoMismatch, i)
		}
	}
	if len(want.BLSPublicKeys) != len(got.BLSPublicKeys) {
		return fmt.Errorf("%w: key count", ErrEpochInfoMismatch)
	}
	for i := range want.BLSPublicKeys {
		if !bytes.Equal(want.BLSPublicKeys[i], got.BLSPublicKeys[i]) {
			return fmt.Errorf("%w: key %d", ErrEpochInfoMismatch, i)
		}
	}
	return nil
}
