package header

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
)

// Errors of header construction and verification. The names follow the
// error names of the specification; the texts follow the reference and are
// informative.
var (
	ErrUnknownBlock           = errors.New("unknown block")
	ErrFutureBlock            = errors.New("block in the future")
	ErrUnknownAncestor        = validator.ErrUnknownAncestor
	ErrInvalidDifficulty      = errors.New("invalid difficulty")
	ErrInvalidTimestamp       = errors.New("invalid timestamp")
	ErrUnauthorized           = errors.New("unauthorized")
	ErrBlacklistedSigner      = errors.New("blacklisted signer")
	ErrInvalidExtraDataFormat = codec.ErrInvalidExtraDataFormat

	ErrEmptyPreparedSeals        = errors.New("zero prepared seals")
	ErrInvalidPreparedSeals      = errors.New("invalid prepared seals")
	ErrEmptyCommittedSeals       = errors.New("zero committed seals")
	ErrInvalidCommittedSeals     = errors.New("invalid committed seals")
	ErrEmptyPrevPreparedSeals    = errors.New("zero prev prepared seals")
	ErrInvalidPrevPreparedSeals  = errors.New("invalid prev prepared seals")
	ErrEmptyPrevCommittedSeals   = errors.New("zero prev committed seals")
	ErrInvalidPrevCommittedSeals = errors.New("invalid prev committed seals")

	ErrInvalidSeal        = errors.New("invalid seal")
	ErrLackOfSealCount    = errors.New("lack of seal count")
	ErrSealerNotValidator = errors.New("sealer is not validator")

	ErrInvalidRandaoReveal = errors.New("failed to verify randao reveal signature")
	ErrInvalidRandaoMix    = errors.New("invalid randao mix")

	ErrGasTipMismatch      = errors.New("gas tip mismatch")
	ErrGasTipUnavailable   = errors.New("WBFT: gas tip of the parent state is not available")
	ErrParentRootEmpty     = errors.New("WBFT: parent state root is empty")
	ErrSnapshotMissing     = errors.New("authority snapshot of the parent is missing")
	ErrInvalidProposal     = errors.New("invalid proposal")
	ErrBlacklistedHash     = errors.New("blacklisted hash")
	ErrUnknownParentHash   = errors.New("unknown parent hash")
	ErrUnsupportedOption   = errors.New("header: option not available")
	ErrMissingConfig       = errors.New("header: environment without configuration or chain")
	ErrMissingRandaoSigner = errors.New("header: no randao signer")
)

// StepError is the error of the first failing step of an ordered verification
// procedure: "P1" .. "P7", "V0a", "V0b", "H1" .. "H21" or a Part B step name.
// Class is the specification error name. errors.Is and errors.As reach Err.
type StepError struct {
	Step  string
	Class string
	Err   error
}

func (e *StepError) Error() string {
	return fmt.Sprintf("%s: %v", e.Step, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }

func stepErr(step, class string, err error) error {
	return &StepError{Step: step, Class: class, Err: err}
}

// GasTipMismatchError reports a header gas tip that differs from the gas tip
// of its parent state.
type GasTipMismatchError struct {
	Have, Want string
}

func (e *GasTipMismatchError) Error() string {
	return fmt.Sprintf("gas tip mismatch: have %s, want %s", e.Have, e.Want)
}

func (e *GasTipMismatchError) Unwrap() error { return ErrGasTipMismatch }
