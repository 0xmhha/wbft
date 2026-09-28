package header

import (
	"time"

	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator/source"
)

// Env is what the header rules read from outside the header. The runner,
// the consensus service and the vector adapter build it.
type Env struct {
	Config *types.Config
	Chain  types.ChainReader

	// BadBlock reports a block hash recorded as bad (step P2). Nil means
	// none is.
	BadBlock func(types.Hash) bool

	// PartB runs the execution-side steps of the ordered procedures (P4,
	// P5, H3, H5 .. H9, H13, H14). Nil skips them.
	PartB PartB

	// Snapshots gives the authority snapshot of an executed block (steps
	// H15b and H21). Nil means no snapshot is available.
	Snapshots SnapshotReader

	// Now is the verifier's clock (step H2 and the future-proposal wait).
	// It must be set for VerifyHeader and VerifyProposal.
	Now func() time.Time
}

// PartB is the application hook for the execution-side steps. It runs one
// step at its position in the ordered procedure; body is nil for header-only
// verification and parent is nil for the steps before H11.
type PartB interface {
	VerifyPartB(step string, h, parent *types.Header, body types.BodyRaw) error
}

// SnapshotReader is the read side of the authority snapshot cache.
type SnapshotReader interface {
	Get(hash types.Hash) (*source.AuthoritySnapshot, bool)
}

// Mode tells whether a missing parent snapshot skips the state-dependent
// steps (HeaderOnly: import, synchronisation) or fails them (Proposal).
type Mode uint8

// Modes.
const (
	HeaderOnly Mode = iota
	Proposal
)

// Options select the variant of header verification.
type Options struct {
	// CheckSeals runs step H17. It is false only for proposal verification.
	CheckSeals bool
	// Mode selects the handling of a missing parent snapshot.
	Mode Mode
}

func (env *Env) partB(step string, h, parent *types.Header, body types.BodyRaw) error {
	if env.PartB == nil {
		return nil
	}
	if err := env.PartB.VerifyPartB(step, h, parent, body); err != nil {
		return stepErr(step, "PartB", err)
	}
	return nil
}
