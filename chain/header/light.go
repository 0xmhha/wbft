package header

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// LightResult is the verdict of VerifyLight.
type LightResult uint8

// Light verification verdicts.
const (
	Valid        LightResult = iota // every checked rule holds
	Invalid                         // a rule is violated
	CannotDecide                    // an input needed for a decision is missing
)

func (r LightResult) String() string {
	switch r {
	case Valid:
		return "VALID"
	case Invalid:
		return "INVALID"
	case CannotDecide:
		return "CANNOT_DECIDE"
	}
	return fmt.Sprintf("LightResult(%d)", uint8(r))
}

// TrustedEpochs gives a light verifier the validator sets it derived from
// epoch headers it has itself accepted, back to the genesis header.
type TrustedEpochs interface {
	// ValidatorsAt returns the set of height n whose parent has the given
	// hash, or an error when a needed epoch header is not known.
	ValidatorsAt(n types.Height, parentHash types.Hash) (*validator.Set, error)
}

// LightInputs configure VerifyLight.
type LightInputs struct {
	Config  *types.Config
	Trusted TrustedEpochs
	// PartB, if set, runs the header-only execution-side steps (H3, H5 ..
	// H9, H13, H14) at their positions.
	PartB PartB
	// Now, if set, applies the future-time rule H2 (CannotDecide).
	Now func() time.Time
}

// ErrLightMissing is the reason of a CannotDecide verdict.
var ErrLightMissing = errors.New("light: missing input")

// VerifyLight decides whether h, with its parent (whose block hash must be
// h.ParentHash), is a correctly finalized WBFT header, using only headers:
// the rules H4, H11, H12, H15a, H16 .. H20 of header verification and the
// EpochInfo presence rule. It returns the verdict and, for Invalid and
// CannotDecide, the reason.
//
// Spec: WBFT-HDR-140, WBFT-HDR-141, WBFT-HDR-142, WBFT-HDR-130
func VerifyLight(in LightInputs, h, parent *types.Header) (LightResult, error) {
	if h.Number.IsZero() {
		return CannotDecide, fmt.Errorf("%w: genesis", ErrLightMissing)
	}
	if parent == nil {
		return CannotDecide, fmt.Errorf("%w: parent", ErrLightMissing)
	}
	v, err := in.Trusted.ValidatorsAt(h.Number, h.ParentHash)
	if err != nil {
		return CannotDecide, fmt.Errorf("%w: validator set: %v", ErrLightMissing, err)
	}
	if in.Now != nil {
		adjusted := in.Now().Add(time.Duration(in.Config.Base().AllowedFutureBlockTime) * time.Second).Unix()
		if h.Time > uint64(adjusted) {
			return CannotDecide, fmt.Errorf("%w: future header", ErrLightMissing)
		}
	}
	partB := func(step string, p *types.Header) error {
		if in.PartB == nil {
			return nil
		}
		return in.PartB.VerifyPartB(step, h, p, nil)
	}
	if err := partB("H3", nil); err != nil {
		return Invalid, err
	}
	if h.Difficulty == nil || h.Difficulty.Cmp(big.NewInt(types.WBFTDifficulty)) != 0 {
		return Invalid, stepErr("H4", "ErrInvalidDifficulty", ErrInvalidDifficulty)
	}
	for _, step := range []string{"H5", "H6", "H7", "H8", "H9"} {
		if err := partB(step, nil); err != nil {
			return Invalid, err
		}
	}
	// H11 compares the low 64 bits of the parent number with the full
	// Number - 1.
	want, _ := h.Number.Sub(types.HeightFromUint64(1))
	if types.HeightFromUint64(parent.Number.RefLow64()).Cmp(want) != 0 || codec.BlockHash(parent) != h.ParentHash { //wbft:low64 HH-21
		return Invalid, stepErr("H11", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	if parent.Time+in.Config.ConfigAt(h.Number).BlockPeriodSeconds > h.Time {
		return Invalid, stepErr("H12", "ErrInvalidTimestamp", ErrInvalidTimestamp)
	}
	for _, step := range []string{"H13", "H14"} {
		if err := partB(step, parent); err != nil {
			return Invalid, err
		}
	}
	if !v.Contains(h.Coinbase) {
		return Invalid, stepErr("H15a", "ErrUnauthorized", ErrUnauthorized)
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return Invalid, stepErr("H16", "ErrInvalidExtraDataFormat", ErrInvalidExtraDataFormat)
	}
	if err := verifySeals(h, v, x); err != nil {
		return Invalid, stepErr("H17", className(err), err)
	}
	if err := ecdsa.CheckSigner(codec.RandaoData(in.Config.ChainID, h.Number), x.RandaoReveal, h.Coinbase); err != nil {
		return Invalid, stepErr("H18", "ErrInvalidRandaoReveal", fmt.Errorf("%w: %w", ErrInvalidRandaoReveal, err))
	}
	if mix := RandaoMix(parent.MixDigest, x.RandaoReveal); mix != h.MixDigest {
		return Invalid, stepErr("H19", "ErrInvalidRandaoMix", ErrInvalidRandaoMix)
	}
	if h.Number.CmpUint64(2) >= 0 {
		vp, err := in.Trusted.ValidatorsAt(parent.Number, parent.ParentHash)
		if err != nil {
			return CannotDecide, fmt.Errorf("%w: validator set of the parent: %v", ErrLightMissing, err)
		}
		if err := verifyPrevSeals(parent, vp, x); err != nil {
			return Invalid, stepErr("H20", className(err), err)
		}
	}
	// Spec: WBFT-EPOCH-006, WBFT-HDR-131
	isEpoch, err := validator.IsEpochBlock(in.Config, h.Number)
	if err != nil {
		return CannotDecide, err
	}
	if (x.EpochInfo != nil) != isEpoch {
		return Invalid, fmt.Errorf("EpochInfo presence does not match the epoch schedule")
	}
	return Valid, nil
}
