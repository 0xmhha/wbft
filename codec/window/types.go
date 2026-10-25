// Package window provides an explicit codec for participation observations.
// It does not enable a chain rule, change the legacy codec, authenticate a
// historical authority, or apply observations to selection or rewards.
package window

import (
	"math/big"

	"github.com/0xmhha/wbft/types"
)

// Limits are required structural bounds supplied by the caller. They have no
// defaults and do not replace admission, signature-work or state-storage limits.
type Limits struct {
	ExtraBytes     uint64
	Proofs         uint32
	SettlementRows uint32
	Validators     uint32
}

// Proof carries a subset certificate for a historical target. A verified
// carrier proves inclusion, not signature creation or receipt time. Chain ancestry,
// historical keys, final round, carrier window and BLS validity need a separate
// verifier. Finality quorum requirements remain separate from these subsets.
type Proof struct {
	Height    types.Height
	Hash      types.Hash
	Round     uint32
	Authority types.Hash
	Phase     types.SealType
	Bitmap    []byte
	Signature []byte
}

// Counts contains non-negative phase counts for one address. Every observed
// count is at most its eligible count. These are observations, not fee weights.
type Counts struct {
	Address         types.Address
	EligiblePrepare *big.Int
	EligibleCommit  *big.Int
	ObservedPrepare *big.Int
	ObservedCommit  *big.Int
}

// Settlement contains the new observations in (Previous, Through]. Rows use
// strictly increasing address order. An empty interval has no rows.
type Settlement struct {
	Previous types.Height
	Through  types.Height
	Rows     []Counts
}

// RecentSettlement replaces settled counts with the inclusive [From, Through]
// matured-target window. Previous remains the prior settlement cursor. An
// empty window has From == Through+1 and no rows. It is never a signed delta.
type RecentSettlement struct {
	Previous types.Height
	Through  types.Height
	From     types.Height
	Rows     []Counts
}

// Observation binds the parent and resulting observation state to the carrier.
// Settlement is nil outside an epoch. This codec does not decide epoch status
// or authenticate the roots against a state transition.
type Observation struct {
	// Version zero retains the original version-one cumulative format.
	Version uint64
	// Recent is a complete replacement snapshot for version two only.
	Recent          *RecentSettlement
	PolicyDigest    types.Hash
	ParentStateRoot types.Hash
	ResultStateRoot types.Hash
	Settlement      *Settlement
}

// Extra is the explicit four-item envelope [2, legacy, proofs, observation].
// Legacy remains a nested ten-item list. Observation is present on every block.
type Extra struct {
	Legacy      *types.WBFTExtra
	Proofs      []Proof
	Observation Observation
}

// Member is an authority entry in historical signer-index order. The codec
// commits this order without sorting addresses or establishing key ownership.
type Member struct {
	Address types.Address
	Key     []byte
}
