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
// The ordered procedure follows verifyHeader, verifyCascadingFields,
// verifySigner, verifySeals, verifyPrevSeals and verifyGasTip of
// consensus/wbft/engine/engine.go, and verifyHeader, VerifyHeaders and
// GetValidatorsForVerifying of consensus/wbft/backend/engine.go of
// go-stablenet (commit 740526d03).

package header

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
	"github.com/holiman/uint256"
)

// ValidatorsForVerifying returns the validator set V of the height of h (V0a)
// and the set Vp of the height of its parent (V0b). Every failure of V0a is
// ErrUnknownAncestor. For uint64(Number) >= 2 the parent is the last element
// of parents, or the stored header (ParentHash, uint64(Number) - 1); a missing
// parent is ErrUnknownAncestor and other failures of V0b are returned as they
// are. For lower numbers Vp is V.
//
// Spec: WBFT-HDR-070, WBFT-VAL-010
func ValidatorsForVerifying(env *Env, h *types.Header, parents []*types.Header) (v, vp *validator.Set, err error) {
	v, err = validator.ValidatorsAt(env.Chain, env.Config, h.Number, h.ParentHash, parents)
	if err != nil {
		return nil, nil, stepErr("V0a", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	n := h.Number.RefLow64() //wbft:low64 HH-45
	if n < 2 {
		return v, v, nil
	}
	var parent *types.Header
	var rest []*types.Header
	if len(parents) == 0 {
		parent = env.Chain.Header(h.ParentHash, n-1)
	} else {
		parent, rest = parents[len(parents)-1], parents[:len(parents)-1]
	}
	if parent == nil {
		return nil, nil, stepErr("V0b", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	vp, err = validator.ValidatorsAt(env.Chain, env.Config, parent.Number, parent.ParentHash, rest)
	if err != nil {
		return nil, nil, stepErr("V0b", "", err)
	}
	return v, vp, nil
}

// VerifyHeader verifies h with the preceding headers parents (oldest first;
// empty for a single header): first the validator sets (V0a, V0b), then the
// steps H1 .. H21 in order. It returns the StepError of the first failing
// step, or nil.
//
// Spec: WBFT-HDR-080
func VerifyHeader(env *Env, h *types.Header, parents []*types.Header, opt Options) error {
	if env.Config == nil || env.Chain == nil {
		return ErrMissingConfig
	}
	v, vp, err := ValidatorsForVerifying(env, h, parents)
	if err != nil {
		return err
	}
	return verifySteps(env, h, parents, v, vp, opt, nil)
}

// VerifyHeaderBatch verifies hs in input order, each with the preceding
// headers of the batch as parents. After the first header that is not
// accepted, every remaining header is reported as ErrUnknownAncestor without
// verifying it.
//
// Spec: WBFT-HDR-120
func VerifyHeaderBatch(env *Env, hs []*types.Header, opt Options) []error {
	out := make([]error, len(hs))
	failed := false
	for i, h := range hs {
		if failed {
			out[i] = ErrUnknownAncestor
			continue
		}
		out[i] = VerifyHeader(env, h, hs[:i], opt)
		failed = out[i] != nil
	}
	return out
}

// VerifyHeaders is VerifyHeaderBatch that delivers the results in input order
// on the returned channel from a goroutine of its own. Delivery stops early
// when ctx is done; the channel is closed after the last result.
//
// Spec: WBFT-HDR-120
func VerifyHeaders(ctx context.Context, env *Env, hs []*types.Header, opt Options) <-chan error {
	results := make(chan error, len(hs))
	go func() {
		defer close(results)
		failed := false
		for i, h := range hs {
			var err error
			if failed {
				err = ErrUnknownAncestor
			} else {
				err = VerifyHeader(env, h, hs[:i], opt)
			}
			failed = failed || err != nil
			select {
			case <-ctx.Done():
				return
			case results <- err:
			}
		}
	}()
	return results
}

// verifySteps runs H1 .. H21. body is passed to Part B steps (nil for
// header-only verification).
func verifySteps(env *Env, h *types.Header, parents []*types.Header, v, vp *validator.Set, opt Options, body types.BodyRaw) error {
	// H1: a header without Number cannot be represented (Number is always
	// present in types.Header).

	// H2
	//
	// Spec: WBFT-HDR-081
	afbt := env.Config.Base().AllowedFutureBlockTime
	adjusted := env.Now().Add(time.Duration(afbt) * time.Second).Unix()
	if h.Time > uint64(adjusted) {
		return stepErr("H2", "ErrFutureBlock", ErrFutureBlock)
	}
	// H3
	if err := env.partB("H3", h, nil, body); err != nil {
		return err
	}
	// H4
	//
	// Spec: WBFT-HDR-082, WBFT-PARAM-010
	if h.Difficulty == nil || h.Difficulty.Cmp(big.NewInt(types.WBFTDifficulty)) != 0 {
		return stepErr("H4", "ErrInvalidDifficulty", ErrInvalidDifficulty)
	}
	// H5 .. H9
	for _, step := range []string{"H5", "H6", "H7", "H8", "H9"} {
		if err := env.partB(step, h, nil, body); err != nil {
			return err
		}
	}
	// H10
	//
	// Spec: WBFT-HDR-083
	n := h.Number.RefLow64() //wbft:low64 HH-20
	if n == 0 {
		return nil
	}
	// H11
	//
	// Spec: WBFT-HDR-084
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = env.Chain.Header(h.ParentHash, n-1) //wbft:low64 HH-21
	}
	if parent == nil || parent.Number.RefLow64() != n-1 || codec.BlockHash(parent) != h.ParentHash { //wbft:low64 HH-21
		return stepErr("H11", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	// H12: the block period of the child's height.
	//
	// Spec: WBFT-HDR-085, WBFT-PARAM-053
	if parent.Time+env.Config.ConfigAt(h.Number).BlockPeriodSeconds > h.Time {
		return stepErr("H12", "ErrInvalidTimestamp", ErrInvalidTimestamp)
	}
	// H13, H14
	for _, step := range []string{"H13", "H14"} {
		if err := env.partB(step, h, parent, body); err != nil {
			return err
		}
	}
	// H15a. The genesis test of the reference signer check is not reached
	// after H10 and is kept with the same truncation.
	//
	// Spec: WBFT-HDR-086
	if h.Number.RefLow64() == 0 { //wbft:low64 HH-26
		return stepErr("H15a", "ErrUnknownBlock", ErrUnknownBlock)
	}
	if !v.Contains(h.Coinbase) {
		return stepErr("H15a", "ErrUnauthorized", ErrUnauthorized)
	}
	// H15b: blacklist at the parent state, from the parent's snapshot.
	if s, ok := env.snapshot(h.ParentHash); ok {
		if s.Eligibility(h.Coinbase) == types.Ineligible {
			return stepErr("H15b", "ErrBlacklistedSigner", fmt.Errorf("%w: %s", ErrBlacklistedSigner, h.Coinbase.Hex()))
		}
	} else if opt.Mode == Proposal {
		return stepErr("H15b", "ErrSnapshotMissing", ErrSnapshotMissing)
	}
	// H16: any vanity is accepted.
	//
	// Spec: WBFT-HDR-088, WBFT-HDR-017
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return stepErr("H16", "ErrInvalidExtraDataFormat", ErrInvalidExtraDataFormat)
	}
	// H17
	if opt.CheckSeals {
		if err := verifySeals(h, v, x); err != nil {
			return stepErr("H17", className(err), err)
		}
	}
	// H18
	//
	// Spec: WBFT-HDR-089
	if err := ecdsa.CheckSigner(codec.RandaoData(env.Config.ChainID, h.Number), x.RandaoReveal, h.Coinbase); err != nil {
		return stepErr("H18", "ErrInvalidRandaoReveal", fmt.Errorf("%w: %w", ErrInvalidRandaoReveal, err))
	}
	// H19
	//
	// Spec: WBFT-HDR-090
	if mix := RandaoMix(parent.MixDigest, x.RandaoReveal); mix != h.MixDigest {
		return stepErr("H19", "ErrInvalidRandaoMix", fmt.Errorf("%w: have %x, want %x", ErrInvalidRandaoMix, h.MixDigest, mix))
	}
	// H20
	//
	// Spec: WBFT-HDR-091, WBFT-HDR-103
	if h.Number.CmpUint64(1) > 0 {
		if err := verifyPrevSeals(parent, vp, x); err != nil {
			return stepErr("H20", className(err), err)
		}
	}
	// H21
	if err := env.gasTipStep(h, x, opt); err != nil {
		return err
	}
	return nil
}

func (env *Env) snapshot(hash types.Hash) (snap interface {
	Eligibility(types.Address) types.Eligibility
	GasTip() *uint256.Int
}, ok bool) {
	if env.Snapshots == nil {
		return nil, false
	}
	s, ok := env.Snapshots.Get(hash)
	if !ok || s == nil {
		return nil, false
	}
	return s, true
}

// gasTipStep is H21: the gas tip of h against the parent state. The parent is
// read again from the chain by (ParentHash, uint64(Number) - 1), ignoring the
// batch. Only a mismatch fails; a missing parent, an empty parent root or a
// missing snapshot skip the check, except that a missing snapshot fails in
// Proposal mode.
//
// Spec: WBFT-HDR-111
func (env *Env) gasTipStep(h *types.Header, x *types.WBFTExtra, opt Options) error {
	parent := env.Chain.Header(h.ParentHash, h.Number.RefLow64()-1) //wbft:low64 HH-28
	if parent == nil || parent.Root == (types.Hash{}) {
		return nil
	}
	s, ok := env.snapshot(h.ParentHash)
	if !ok {
		if opt.Mode == Proposal {
			return stepErr("H21", "ErrSnapshotMissing", ErrSnapshotMissing)
		}
		return nil
	}
	if err := compareGasTip(x, s.GasTip()); err != nil {
		return stepErr("H21", "GasTipMismatchError", err)
	}
	return nil
}

// CheckGasTip compares the gas tip in the extra of h with the gas tip of the
// parent state.
//
// Spec: WBFT-HDR-111
func CheckGasTip(h *types.Header, parentGasTip *uint256.Int) error {
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return err
	}
	if parentGasTip == nil {
		return ErrGasTipUnavailable
	}
	return compareGasTip(x, parentGasTip)
}

func compareGasTip(x *types.WBFTExtra, want *uint256.Int) error {
	w := want.ToBig()
	if x.GasTip == nil || x.GasTip.Cmp(w) != 0 {
		have := "<nil>"
		if x.GasTip != nil {
			have = x.GasTip.String()
		}
		return &GasTipMismatchError{Have: have, Want: w.String()}
	}
	return nil
}

// verifySeals is H17: the prepared and then the committed seal of h against
// V, each present with a non-empty signature and valid for (V, h,
// Extra.Round).
//
// A present seal with an empty signature counts as no seal.
//
// Spec: WBFT-HDR-102, WBFT-ENC-043
func verifySeals(h *types.Header, v *validator.Set, x *types.WBFTExtra) error {
	if h.Number.RefLow64() == 0 { //wbft:low64 HH-27
		return nil
	}
	if x.PreparedSeal == nil || len(x.PreparedSeal.Signature) == 0 {
		return ErrEmptyPreparedSeals
	}
	if err := VerifyAggregatedSeal(v, h, x.Round, x.PreparedSeal, types.PrepareSeal); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPreparedSeals, err)
	}
	if x.CommittedSeal == nil || len(x.CommittedSeal.Signature) == 0 {
		return ErrEmptyCommittedSeals
	}
	if err := VerifyAggregatedSeal(v, h, x.Round, x.CommittedSeal, types.CommitSeal); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCommittedSeals, err)
	}
	return nil
}

// verifyPrevSeals is H20: the previous-block seals of the child against the
// parent header, Vp and Extra.PrevRound. A genesis parent is not checked.
//
// Spec: WBFT-HDR-103
func verifyPrevSeals(parent *types.Header, vp *validator.Set, x *types.WBFTExtra) error {
	if parent.Number.IsZero() {
		return nil
	}
	if x.PrevPreparedSeal == nil || len(x.PrevPreparedSeal.Signature) == 0 {
		return ErrEmptyPrevPreparedSeals
	}
	if err := VerifyAggregatedSeal(vp, parent, x.PrevRound, x.PrevPreparedSeal, types.PrepareSeal); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrevPreparedSeals, err)
	}
	if x.PrevCommittedSeal == nil || len(x.PrevCommittedSeal.Signature) == 0 {
		return ErrEmptyPrevCommittedSeals
	}
	if err := VerifyAggregatedSeal(vp, parent, x.PrevRound, x.PrevCommittedSeal, types.CommitSeal); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrevCommittedSeals, err)
	}
	return nil
}

// className returns the specification error name of a seal error.
func className(err error) string {
	for _, c := range []struct {
		err  error
		name string
	}{
		{ErrEmptyPreparedSeals, "ErrEmptyPreparedSeals"},
		{ErrInvalidPreparedSeals, "ErrInvalidPreparedSeals"},
		{ErrEmptyCommittedSeals, "ErrEmptyCommittedSeals"},
		{ErrInvalidCommittedSeals, "ErrInvalidCommittedSeals"},
		{ErrEmptyPrevPreparedSeals, "ErrEmptyPrevPreparedSeals"},
		{ErrInvalidPrevPreparedSeals, "ErrInvalidPrevPreparedSeals"},
		{ErrEmptyPrevCommittedSeals, "ErrEmptyPrevCommittedSeals"},
		{ErrInvalidPrevCommittedSeals, "ErrInvalidPrevCommittedSeals"},
	} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return ""
}
