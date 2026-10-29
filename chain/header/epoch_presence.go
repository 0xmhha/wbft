package header

import (
	"errors"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/types"
)

// checkEpochInfoPresence reads only the configured full-height schedule and
// decoded metadata. It neither opens state nor verifies epoch candidates.
func checkEpochInfoPresence(cfg *types.Config, h *types.Header, x *types.WBFTExtra) error {
	if cfg == nil {
		return ErrMissingConfig
	}
	if h == nil {
		return ErrInvalidProposal
	}
	if x == nil {
		return ErrInvalidExtraDataFormat
	}
	isEpoch, err := validator.IsEpochBlock(cfg, h.Number)
	if err != nil {
		return err
	}
	if isEpoch && x.EpochInfo == nil {
		return validator.ErrEpochInfoNil
	}
	if !isEpoch && x.EpochInfo != nil {
		return epoch.ErrEpochInfoIsNotNil
	}
	return nil
}

func epochInfoPresenceError(cfg *types.Config, h *types.Header, x *types.WBFTExtra) error {
	err := checkEpochInfoPresence(cfg, h, x)
	if err == nil {
		return nil
	}
	class := ""
	switch {
	case errors.Is(err, validator.ErrEpochInfoNil):
		class = "ErrEpochInfoNil"
	case errors.Is(err, epoch.ErrEpochInfoIsNotNil):
		class = "ErrEpochInfoIsNotNil"
	case errors.Is(err, validator.ErrZeroEpochLength):
		class = "ErrZeroEpochLength"
	case errors.Is(err, ErrMissingConfig):
		class = "ErrMissingConfig"
	case errors.Is(err, ErrInvalidProposal):
		class = "ErrInvalidProposal"
	case errors.Is(err, ErrInvalidExtraDataFormat):
		class = "ErrInvalidExtraDataFormat"
	}
	return stepErr("epoch_info_presence", class, err)
}
