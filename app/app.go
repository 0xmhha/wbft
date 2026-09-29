package app

import (
	"context"

	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/types"
)

// Application is implemented by the execution layer. Each method is called
// in one context (the letters of the app-interface design, section 2.1):
//
//   - C: the consensus goroutine. The call must not wait for locks, the
//     network or other goroutines; disk reads and CPU work only.
//   - K: the commit goroutine, one call at a time in height order.
//   - S: start-up and shut-down.
//
// Calls from different contexts run concurrently; a query in context C that
// overlaps a FinalizeBlock sees the chain either before or after the import.
type Application interface {
	// ChainReader answers header queries in contexts C and A.
	//
	// Spec: WBFT-APP-001, WBFT-APP-003
	types.ChainReader

	// Info reports the application's version, chain and head (context S).
	Info(ctx context.Context) (InfoResponse, error)

	// IsBadBlock reports whether the block is recorded as bad (context C;
	// never blocks). The record keeps the ten highest bad blocks.
	//
	// Spec: WBFT-APP-004
	IsBadBlock(hash types.Hash) bool

	// ReadyToBuild tells the block builder that a round started (context
	// C; never blocks). The builder waits req.Wait, assembles a block on
	// req.Parent and hands it to Consensus.SubmitProposal, unless req.Done
	// is closed first.
	ReadyToBuild(req BuildRequest)

	// VerifyPartB runs one execution-side step of proposal or header
	// verification (contexts C and A). body is nil for header-only
	// verification and parent is nil for the steps before H11.
	VerifyPartB(step string, h, parent *types.Header, body types.BodyRaw) error

	// FinalizeBlock executes and stores a decided block and makes it the
	// head (context K). It is idempotent: a block that is already the head
	// returns AlreadyHead. The application writes block, receipts, state
	// and head atomically, since ctx may be cancelled.
	FinalizeBlock(ctx context.Context, req FinalizeRequest) (FinalizeResponse, error)
}

// ProposalExecutor is an optional Application extension that executes a
// proposal before the node votes for it (feature "execute_proposal"). The
// first part of the project (W0-W5) never calls it.
type ProposalExecutor interface {
	ExecuteProposal(ctx context.Context, b *types.Block) (ExecVerdict, error)
}

// DecidedBlockSender is an optional Application extension that sends a
// decided block to a peer that is behind (feature "send_decided_block").
// The first part of the project (W0-W5) never calls it.
type DecidedBlockSender interface {
	// SendDecidedBlock sends the canonical block with that hash to one
	// peer. It never blocks and returns false if the block was not queued.
	SendDecidedBlock(peer types.Address, hash types.Hash) bool
}

// Consensus is implemented by the consensus node and called by the
// application from its own goroutines (context A). Notifications (the On
// methods and SubmitProposal) never block. No method waits for the
// consensus goroutine; only PrepareConsensusFields may wait, for the
// authority snapshot of the parent. After the node stopped, notifications
// are dropped and the other methods return ErrStopped.
type Consensus interface {
	// PrepareConsensusFields fills the consensus fields of a proposal
	// header under construction (coinbase, time, randao, the previous
	// seals, the gas tip).
	PrepareConsensusFields(ctx context.Context, h *types.Header) (*types.Header, error)
	// EpochInfo computes the epoch information of an epoch block whose
	// execution is in progress in ctx.
	EpochInfo(ctx context.Context, h *types.Header) (*types.EpochInfo, error)
	// VerifyEpochInfo checks the epoch information of an imported epoch
	// block against the state of its execution in ctx.
	VerifyEpochInfo(ctx context.Context, h *types.Header) error
	// SubmitProposal hands a block assembled after ReadyToBuild to the
	// consensus core.
	SubmitProposal(b *types.Block)
	// VerifyHeader verifies a header on the import path.
	VerifyHeader(ctx context.Context, h *types.Header, opt VerifyOptions) error
	// VerifyHeaders verifies a batch of headers; the channel yields one
	// result per header in order.
	VerifyHeaders(ctx context.Context, hs []*types.Header, opt VerifyOptions) <-chan error
	// OnBlockExecuted hands over the authority snapshot of an executed
	// block. The application calls it before the head notification of
	// that block.
	OnBlockExecuted(s *source.AuthoritySnapshot)
	// OnNewHead reports a new canonical head. Pending notifications are
	// coalesced to the latest.
	//
	// Spec: WBFT-APP-070, WBFT-APP-071
	OnNewHead(ev NewHead)
	// OnSyncState reports the start and the end of a chain
	// synchronisation.
	OnSyncState(s SyncState)
	// OnImportFailed reports a block that failed import.
	OnImportFailed(f ImportFailure)
}
