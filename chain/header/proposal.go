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
// Proposal construction follows Prepare, WriteRandao, WritePrevSeals and
// WriteGasTip of consensus/wbft/engine/engine.go; proposal verification
// follows Backend.Verify of consensus/wbft/backend/backend.go and
// VerifyBlockProposal of consensus/wbft/engine/engine.go of go-stablenet
// (commit 740526d03).

package header

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// RandaoSigner signs the randao data of a proposal with the node key: it
// returns ecdsa_sign(node_key, data), the signature over keccak256(data).
type RandaoSigner interface {
	SignRandao(data []byte) ([]byte, error)
}

// ProposalInputs are the inputs of PrepareProposal besides the skeleton.
type ProposalInputs struct {
	// Coinbase is the address of the node key.
	Coinbase types.Address
	// Signer signs the randao reveal.
	Signer RandaoSigner
	// ExtraPrepared and ExtraCommitted are the extra seals of the head the
	// consensus core collected, with their indices in the head's validator
	// set.
	ExtraPrepared, ExtraCommitted []types.SealEntry
	// ParentGasTip is the gas tip of the parent state; nil when it cannot be
	// read, which fails the construction.
	ParentGasTip *uint256.Int

	// The following options are reserved for later protocol revisions.
	// They must be false.
	PrevSealByParentHash  bool
	VerifyMergedPrevSeals bool
	Allow32ByteVanity     bool
}

// PrepareProposal is prepare_proposal_header: it fills the consensus fields
// of a copy of the builder's skeleton. The skeleton carries ParentHash,
// Number, GasLimit, BaseFee, the execution fields and the builder vanity in
// Extra. It sets Coinbase, Nonce, Difficulty, Time = max(parent.Time +
// BlockPeriod(Number), now), and an extra with the randao reveal, for
// Number > 1 the previous-block seals of the canonical header at Number - 1
// merged with the extra seals, and the gas tip; then MixDigest.
//
// The parent is looked up by ParentHash at Number - 1, so a skeleton whose
// ParentHash or Number does not follow a stored parent fails with
// ErrUnknownAncestor.
//
// Spec: WBFT-HDR-042, WBFT-HDR-010, WBFT-HDR-011, WBFT-HDR-012, WBFT-HDR-013, WBFT-HDR-014, WBFT-HDR-016, WBFT-HDR-018, WBFT-HDR-020, WBFT-HDR-021, WBFT-HDR-030, WBFT-HDR-031, WBFT-HDR-032, WBFT-HDR-033, WBFT-HDR-040
func PrepareProposal(env *Env, skeleton *types.Header, in ProposalInputs) (*types.Header, error) {
	if in.PrevSealByParentHash || in.VerifyMergedPrevSeals || in.Allow32ByteVanity {
		return nil, ErrUnsupportedOption
	}
	if env.Config == nil || env.Chain == nil {
		return nil, ErrMissingConfig
	}
	if in.Signer == nil {
		return nil, ErrMissingRandaoSigner
	}
	h := skeleton.Copy()
	h.Coinbase = in.Coinbase
	h.Nonce = types.Nonce{}

	n := h.Number.RefLow64() //wbft:low64 HH-29
	parent := env.Chain.Header(h.ParentHash, n-1)
	if parent == nil {
		return nil, ErrUnknownAncestor
	}
	h.Difficulty = big.NewInt(types.WBFTDifficulty)

	// Spec: WBFT-PARAM-053
	h.Time = parent.Time + env.Config.ConfigAt(h.Number).BlockPeriodSeconds
	if now := uint64(env.Now().Unix()); h.Time < now {
		h.Time = now
	}

	// Gas tip of the parent state.
	gasTipParent := env.Chain.Header(h.ParentHash, h.Number.RefLow64()-1) //wbft:low64 HH-28
	if gasTipParent == nil {
		return nil, ErrUnknownAncestor
	}
	if gasTipParent.Root == (types.Hash{}) {
		return nil, ErrParentRootEmpty
	}
	if in.ParentGasTip == nil {
		return nil, ErrGasTipUnavailable
	}
	gasTip := in.ParentGasTip.ToBig()

	writeRandao := func(x *types.WBFTExtra) error {
		reveal, err := in.Signer.SignRandao(codec.RandaoData(env.Config.ChainID, h.Number))
		if err != nil {
			return fmt.Errorf("failed to sign randao reveal: %w", err)
		}
		x.RandaoReveal = reveal
		return nil
	}
	writeGasTip := func(x *types.WBFTExtra) error {
		x.GasTip = new(big.Int).Set(gasTip)
		return nil
	}
	fns := []func(*types.WBFTExtra) error{writeRandao}
	if h.Number.CmpUint64(1) > 0 {
		last := env.Chain.HeaderByNumber(h.Number.RefLow64() - 1) //wbft:low64 HH-31
		if last == nil {
			return nil, ErrUnknownAncestor
		}
		if !last.Number.IsZero() {
			lx, err := codec.DecodeExtra(last)
			if err != nil {
				return nil, err
			}
			if lx.PreparedSeal == nil {
				return nil, ErrEmptyPreparedSeals
			}
			if lx.CommittedSeal == nil {
				return nil, ErrEmptyCommittedSeals
			}
			prevPrepared := MergeSeals(lx.PreparedSeal, in.ExtraPrepared)
			prevCommitted := MergeSeals(lx.CommittedSeal, in.ExtraCommitted)
			prevRound := lx.Round
			fns = append(fns, func(x *types.WBFTExtra) error {
				x.PrevRound = prevRound
				x.PrevPreparedSeal = prevPrepared
				x.PrevCommittedSeal = prevCommitted
				return nil
			})
		}
	}
	fns = append(fns, writeGasTip)
	x, err := applyExtra(h, fns...)
	if err != nil {
		return nil, fmt.Errorf("failed to write wbft extra: %w", err)
	}
	h.MixDigest = RandaoMix(parent.MixDigest, x.RandaoReveal)
	return h, nil
}

// VerifyProposal is validate_proposal: steps P1 .. P7 in order. When the
// header is from the future (H2) it returns ErrFutureBlock with the time
// until the header time, time.Until(time.Unix(int64(Time), 0)) of the
// verifier's clock; that duration is negative for Time >= 2^63.
//
// Spec: WBFT-HDR-060, WBFT-HDR-061, WBFT-HDR-063
func VerifyProposal(env *Env, b *types.Block) (future time.Duration, err error) {
	// P1
	if b == nil || b.Header == nil {
		return 0, stepErr("P1", "ErrInvalidProposal", ErrInvalidProposal)
	}
	if env.Config == nil || env.Chain == nil {
		return 0, ErrMissingConfig
	}
	h := b.Header
	// P2
	if env.BadBlock != nil && env.BadBlock(codec.BlockHash(h)) {
		return 0, stepErr("P2", "ErrBlacklistedHash", ErrBlacklistedHash)
	}
	// P3
	v, vp, err := ValidatorsForVerifying(env, h, nil)
	if err != nil {
		return 0, err
	}
	// P4, P5
	for _, step := range []string{"P4", "P5"} {
		if err := env.partB(step, h, nil, b.Body); err != nil {
			return 0, err
		}
	}
	// P6
	if err := verifySteps(env, h, nil, v, vp, Options{CheckSeals: false, Mode: Proposal}, b.Body); err != nil {
		if errors.Is(err, ErrFutureBlock) {
			return time.Unix(int64(h.Time), 0).Sub(env.Now()), err
		}
		return 0, err
	}
	// P7
	if env.Chain.HeaderByHash(h.ParentHash) == nil {
		return 0, stepErr("P7", "ErrUnknownParentHash", ErrUnknownParentHash)
	}
	return 0, nil
}
