// Package snetpartb is a stand-in for the execution-side steps of header
// verification (B-03 §1 and §2: H3, H5 .. H9, H13, H14) on the StableNet
// presets. In a node these steps belong to the application (header.PartB).
// The vector adapter uses it to decide the header cases whose verdict an
// execution-side step decides, and tools/headerscan uses it to check the
// headers of a running StableNet network. The proposal body steps P4 and P5
// are not implemented.
//
// The stand-in is temporary: it moves to the execution-layer adapter once
// that adapter exists.
package snetpartb

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/types"
)

// Forks are the fork activations the Part B steps read. A nil field is a
// fork that is not scheduled.
type Forks struct {
	London   *big.Int
	Shanghai *uint64
	Cancun   *uint64
}

// PartB implements header.PartB for a StableNet preset with the given forks.
type PartB struct {
	Forks Forks
}

// ErrStep is returned for a step name the stand-in does not know.
var ErrStep = errors.New("unknown Part B step")

// Constants of the StableNet presets (B-03).
const (
	gasLimitBoundDivisor = 1024
	minGasLimit          = 5000
	initialBaseFee       = 1_000_000_000
	increasingThreshold  = 20
	decreasingThreshold  = 6
	baseFeeChangeRate    = 2
)

var (
	minBaseFee = big.NewInt(20_000_000_000_000)
	maxBaseFee = big.NewInt(20_000_000_000_000_000)
)

func (p *PartB) isLondon(n types.Height) bool {
	return p.Forks.London != nil && p.Forks.London.Cmp(n.Big()) <= 0
}

func timeForked(s *uint64, t uint64) bool { return s != nil && *s <= t }

// VerifyPartB runs one execution-side step.
func (p *PartB) VerifyPartB(step string, h, parent *types.Header, _ types.BodyRaw) error {
	switch step {
	case "H3":
		if h.UncleHash != types.EmptyUncleHash {
			return errors.New("non empty uncle hash")
		}
	case "H5":
		if h.GasLimit > types.MaxGasLimit {
			return fmt.Errorf("invalid gasLimit: have %d, max %d", h.GasLimit, types.MaxGasLimit)
		}
	case "H6":
		if p.isLondon(h.Number) && timeForked(p.Forks.Shanghai, h.Time) {
			return errors.New("wbft does not support shanghai fork")
		}
	case "H7":
		if h.WithdrawalsHash != nil {
			return errors.New("invalid withdrawalsHash")
		}
	case "H8":
		if p.isLondon(h.Number) && timeForked(p.Forks.Cancun, h.Time) {
			return errors.New("wbft does not support cancun fork")
		}
	case "H9":
		switch {
		case h.ExcessBlobGas != nil:
			return errors.New("invalid excessBlobGas")
		case h.BlobGasUsed != nil:
			return errors.New("invalid blobGasUsed")
		case h.ParentBeaconRoot != nil:
			return errors.New("invalid parentBeaconRoot")
		}
	case "H13":
		if h.GasUsed > h.GasLimit {
			return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", h.GasUsed, h.GasLimit)
		}
	case "H14":
		return p.verifyFeeFields(h, parent)
	default:
		return fmt.Errorf("%w %q", ErrStep, step)
	}
	return nil
}

// verifyFeeFields is SNET-BHDR-008 to SNET-BHDR-010 with the base-fee rule
// of B-03 §2.3.
func (p *PartB) verifyFeeFields(h, parent *types.Header) error {
	if !p.isLondon(h.Number) {
		if h.BaseFee != nil {
			return errors.New("invalid baseFee before fork")
		}
		return verifyGasLimit(parent.GasLimit, h.GasLimit)
	}
	parentGasLimit := parent.GasLimit
	if !p.isLondon(parent.Number) {
		parentGasLimit = parent.GasLimit * 2
	}
	if err := verifyGasLimit(parentGasLimit, h.GasLimit); err != nil {
		return err
	}
	if h.BaseFee == nil {
		return errors.New("header is missing baseFee")
	}
	want, err := p.calcBaseFee(parent)
	if err != nil {
		return err
	}
	if h.BaseFee.Cmp(want) != 0 {
		return fmt.Errorf("invalid baseFee: have %s, want %s", h.BaseFee, want)
	}
	return nil
}

func verifyGasLimit(parentGasLimit, gasLimit uint64) error {
	diff := int64(parentGasLimit) - int64(gasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parentGasLimit / gasLimitBoundDivisor
	if uint64(diff) >= limit {
		return fmt.Errorf("invalid gas limit: have %d, want %d +-= %d", gasLimit, parentGasLimit, limit-1)
	}
	if gasLimit < minGasLimit {
		return fmt.Errorf("invalid gas limit below %d", minGasLimit)
	}
	return nil
}

func (p *PartB) calcBaseFee(parent *types.Header) (*big.Int, error) {
	if !p.isLondon(parent.Number) {
		return big.NewInt(initialBaseFee), nil
	}
	if parent.BaseFee == nil {
		return nil, errors.New("parent without baseFee")
	}
	increasingTarget := parent.GasLimit * increasingThreshold / 100
	decreasingTarget := parent.GasLimit * decreasingThreshold / 100
	baseFee := new(big.Int).Set(parent.BaseFee)
	delta := func() *big.Int {
		d := new(big.Int).Mul(parent.BaseFee, big.NewInt(baseFeeChangeRate))
		d.Div(d, big.NewInt(100))
		if d.Sign() == 0 {
			d.SetInt64(1)
		}
		return d
	}
	switch {
	case parent.GasUsed > increasingTarget:
		baseFee.Add(baseFee, delta())
		if maxBaseFee.Sign() != 0 && baseFee.Cmp(maxBaseFee) > 0 {
			baseFee.Set(maxBaseFee)
		}
	case parent.GasUsed < decreasingTarget:
		baseFee.Sub(baseFee, delta())
		if baseFee.Cmp(minBaseFee) < 0 {
			baseFee.Set(minBaseFee)
		}
	}
	return baseFee, nil
}
