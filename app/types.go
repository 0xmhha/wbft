package app

import (
	"math/big"
	"time"

	"github.com/0xmhha/wbft/types"
)

// Major is the major version of the application interface this package
// defines. InfoResponse.AppMajors must contain it.
const Major uint32 = 1

// Features an application may offer in InfoResponse.Features.
const (
	FeatureExecuteProposal  = "execute_proposal"
	FeatureSendDecidedBlock = "send_decided_block"
)

// BuildRequest asks the block builder for a proposal.
type BuildRequest struct {
	// Height is the full number to build: the parent's number + 1.
	Height types.Height
	// Round is the round that requested the build.
	Round types.Round
	// Wait is how long the builder waits before building: the head's time
	// plus the block period minus now for round 0, zero otherwise.
	Wait time.Duration
	// Parent is the head the consensus core saw.
	Parent types.Hash
	// Done is closed when the core leaves Height.
	Done <-chan struct{}
}

// FinalizeRequest hands a decided block to the application.
type FinalizeRequest struct {
	// Block has its seals written into the header.
	Block *types.Block
	// Round is the decided round; the header carries its low 32 bits.
	Round types.Round
}

// FinalizeResponse is the result of FinalizeBlock.
type FinalizeResponse struct {
	Hash types.Hash
	// AlreadyHead reports an idempotent success: the block was the head.
	AlreadyHead bool
}

// HeadPath tells where the header copy of a new head came from.
type HeadPath uint8

// Head paths.
const (
	// SealedLocally: stored by this node's FinalizeBlock with its own
	// quorum of seals.
	SealedLocally HeadPath = iota
	// Imported: a peer's copy through block propagation or the fetcher.
	Imported
	// Synced: stored by the chain synchronisation.
	Synced
)

// String returns the name of the path used in event records.
func (p HeadPath) String() string {
	switch p {
	case SealedLocally:
		return "sealed_locally"
	case Imported:
		return "imported"
	case Synced:
		return "synced"
	}
	return "unknown"
}

// NewHead reports a new canonical head.
type NewHead struct {
	Header *types.Header
	Path   HeadPath
}

// SyncState reports the chain synchronisation of the application.
type SyncState struct {
	// Syncing is true while a synchronisation runs.
	Syncing bool
	// Success is meaningful when Syncing turns false: the synchronisation
	// completed.
	Success bool
}

// ImportFailure reports a block that failed import.
type ImportFailure struct {
	Number types.Height
	Hash   types.Hash
	Path   HeadPath
	// RecordedBad reports that the application recorded the block as bad.
	RecordedBad bool
	Err         *ImportError
}

// VerifyOptions select the variant of header verification.
type VerifyOptions struct {
	// CheckSeals checks the committed seals (step H17).
	CheckSeals bool
}

// InfoResponse describes the application at start-up.
type InfoResponse struct {
	// AppMajors are the supported major versions of this interface.
	AppMajors []uint32
	// Features are the optional features offered (FeatureExecuteProposal,
	// FeatureSendDecidedBlock).
	Features []string
	ChainID  *big.Int
	// GenesisHash is the hash of the genesis block.
	GenesisHash types.Hash
	// ChainConfigJSON is the chain configuration (the chain-level settings
	// of the consensus layer), as JSON.
	ChainConfigJSON []byte
	// AppImprovements lists the names of the improvements the execution
	// layer enabled; the node reports them with source "app".
	AppImprovements []string
	// Head is the application's canonical head.
	Head *types.Header
}

// HasFeature reports whether the response offers the feature.
func (r InfoResponse) HasFeature(name string) bool {
	for _, f := range r.Features {
		if f == name {
			return true
		}
	}
	return false
}

// SupportsMajor reports whether the response lists the major version.
func (r InfoResponse) SupportsMajor(m uint32) bool {
	for _, v := range r.AppMajors {
		if v == m {
			return true
		}
	}
	return false
}

// ExecVerdict is the result of ExecuteProposal. Unknown is never treated
// as Valid.
type ExecVerdict uint8

// Execution verdicts.
const (
	Valid ExecVerdict = iota
	Invalid
	Unknown
)
