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
// The epoch schedule and the validator-set lookup follow IsEpochBlockNumber,
// GetValidators, GetEpochInfo, getEpochInfo and extractEpochInfo of
// consensus/wbft/engine/engine.go of go-stablenet (commit 740526d03).

package validator

import (
	"errors"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// ErrZeroEpochLength is returned when the epoch length in force is 0, which
// a chain configuration accepted by a node never has.
var ErrZeroEpochLength = errors.New("validator: epoch length is 0")

// EpochSchedule returns the anchor and the length of the epoch schedule in
// force at number n: the base epoch length anchored at 0, re-anchored at the
// block of every transition up to n that sets a non-zero epoch length.
//
// Spec: WBFT-EPOCH-001, WBFT-EPOCH-003, WBFT-PARAM-054
func EpochSchedule(cfg *types.Config, n types.Height) (anchor *big.Int, length uint64) {
	anchor = new(big.Int)
	length = cfg.Base().EpochLength
	num := n.Big()
	for _, t := range cfg.EpochTransitions() {
		if t.Block.Cmp(num) > 0 {
			break
		}
		anchor = t.Block
		length = t.Length
	}
	return anchor, length
}

// epochRem returns (n - anchor) mod length over the full values.
func epochRem(cfg *types.Config, n types.Height) (*big.Int, error) {
	anchor, length := EpochSchedule(cfg, n)
	if length == 0 {
		return nil, ErrZeroEpochLength
	}
	rem := new(big.Int).Sub(n.Big(), anchor)
	return rem.Rem(rem, new(big.Int).SetUint64(length)), nil
}

// IsEpochBlock reports whether n is an epoch block: (n - anchor) mod length
// is 0 for the schedule in force at n. Block 0 is an epoch block.
//
// Spec: WBFT-EPOCH-001
func IsEpochBlock(cfg *types.Config, n types.Height) (bool, error) {
	rem, err := epochRem(cfg, n)
	if err != nil {
		return false, err
	}
	return rem.Sign() == 0, nil
}

// LastEpochBlock returns the greatest epoch block at or below n,
// n - ((n - anchor) mod length).
//
// Spec: WBFT-EPOCH-002
func LastEpochBlock(cfg *types.Config, n types.Height) (types.Height, error) {
	rem, err := epochRem(cfg, n)
	if err != nil {
		return types.Height{}, err
	}
	last, _ := n.Sub(types.MustHeightFromBig(rem))
	return last, nil
}

// ValidatorsAt is validators_at(n, parentHash, parents): the genesis
// validators of the configuration for n = 0, and otherwise the set recorded
// in the EpochInfo of the epoch header that governs n (EpochInfoFor), with the
// proposer policy of config_at(n). parents are headers not yet stored, oldest
// first, ending with the parent of n; they are consulted first when the
// lookup walks back.
//
// Spec: WBFT-VAL-004, WBFT-VAL-006, WBFT-VAL-009, WBFT-VAL-011
func ValidatorsAt(chain types.ChainReader, cfg *types.Config, n types.Height, parentHash types.Hash, parents []*types.Header) (*Set, error) {
	if n.IsZero() {
		pol := cfg.Base().ProposerPolicy
		if pol == nil {
			return nil, ErrNoProposerPolicy
		}
		return NewSet(cfg.Init.Validators, cfg.Init.BLSPublicKeys, *pol)
	}
	_, ei, err := EpochInfoFor(chain, cfg, n, parentHash, parents)
	if err != nil {
		return nil, err
	}
	pol := cfg.ConfigAt(n).ProposerPolicy
	if pol == nil {
		return nil, ErrNoProposerPolicy
	}
	return NewSetFromEpochInfo(ei, *pol)
}

// EpochInfoFor returns the number and the EpochInfo of the epoch header that
// governs block n >= 1: the header at last_epoch_block(uint64(n) - 1). The
// header stored as canonical at that index is used if there is one; otherwise
// the lookup walks back from the parent of n, first through parents (last
// element first) and then through stored headers. A missing header is
// ErrUnknownAncestor; an undecodable extra is its decoding error; an epoch
// header without EpochInfo is ErrEpochInfoNil.
//
// Block 1 is governed by the EpochInfo of the genesis header.
//
// Spec: WBFT-HDR-071, WBFT-HDR-121
func EpochInfoFor(chain types.ChainReader, cfg *types.Config, n types.Height, parentHash types.Hash, parents []*types.Header) (types.Height, *types.EpochInfo, error) {
	parentNumber := n.RefLow64() - 1 //wbft:low64 HH-41
	last, err := LastEpochBlock(cfg, types.HeightFromUint64(parentNumber))
	if err != nil {
		return types.Height{}, nil, err
	}
	if h := chain.HeaderByNumber(last.RefLow64()); h != nil { //wbft:low64 HH-43
		return extractEpochInfo(h)
	}
	pending := parents
	var block *types.Header
	for {
		if len(pending) > 0 {
			block = pending[len(pending)-1]
			pending = pending[:len(pending)-1]
		} else {
			block = chain.Header(parentHash, parentNumber)
		}
		if block == nil {
			return types.Height{}, nil, ErrUnknownAncestor
		}
		if last.Cmp(block.Number) == 0 {
			break
		}
		parentHash, parentNumber = block.ParentHash, block.Number.RefLow64()-1 //wbft:low64 HH-44
	}
	return extractEpochInfo(block)
}

// GoverningEpochInfo returns the EpochInfo that governs h: the genesis header
// governs itself, every other header is governed by EpochInfoFor(h.Number,
// h.ParentHash).
func GoverningEpochInfo(chain types.ChainReader, cfg *types.Config, h *types.Header, parents []*types.Header) (types.Height, *types.EpochInfo, error) {
	if h.Number.IsZero() {
		return extractEpochInfo(h)
	}
	return EpochInfoFor(chain, cfg, h.Number, h.ParentHash, parents)
}

func extractEpochInfo(h *types.Header) (types.Height, *types.EpochInfo, error) {
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return types.Height{}, nil, err
	}
	if x.EpochInfo == nil {
		return types.Height{}, nil, ErrEpochInfoNil
	}
	return h.Number, x.EpochInfo, nil
}
