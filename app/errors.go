package app

import (
	"errors"
	"fmt"
)

// Errors returned by the application to the consensus node. Wrap them to
// add detail; the node tells them apart with errors.Is.
var (
	// ErrInvalidBlock: the block failed header, body, execution or state
	// validation. Wrap it in *ImportError to report the step.
	ErrInvalidBlock = errors.New("app: invalid block")
	// ErrTemporary: the operation may succeed if retried (disk, lock, I/O).
	ErrTemporary = errors.New("app: temporary failure")
	// ErrConflictingBlock: a different block is already canonical at this
	// height.
	ErrConflictingBlock = errors.New("app: conflicting canonical block")
	// ErrStateUnavailable: the state after that block is not kept.
	ErrStateUnavailable = errors.New("app: state unavailable")
	// ErrNoExecutionContext: ctx carries no block execution in progress.
	ErrNoExecutionContext = errors.New("app: no execution in context")
	// ErrUnsupported: an optional feature is not implemented.
	ErrUnsupported = errors.New("app: unsupported")
)

// Errors returned by the consensus node to the application.
var (
	ErrStopped      = errors.New("wbft: stopped")
	ErrNoSigner     = errors.New("wbft: no signer configured")
	ErrNotValidator = errors.New("wbft: local node is not a validator at this height")
)

// ImportError carries the failing verification step and its error class.
type ImportError struct {
	// Step is the step ID of the failing check ("H17", "P4", ...).
	Step string
	// Class is the name of the error class.
	Class string
	Err   error
}

func (e *ImportError) Error() string {
	return fmt.Sprintf("import failed at %s (%s): %v", e.Step, e.Class, e.Err)
}

// Unwrap returns the underlying error.
func (e *ImportError) Unwrap() error { return e.Err }
