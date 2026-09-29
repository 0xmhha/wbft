package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// service implements app.Consensus for a node.
type service struct{ n *Node }

var _ app.Consensus = (*service)(nil)

// ready returns the node's state for a service call, or ErrStopped.
func (s *service) ready() (*chainView, *privval.FileSigner, error) {
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != started || n.view == nil {
		return nil, nil, app.ErrStopped
	}
	return n.view, n.signer, nil
}

// PrepareConsensusFields fills the consensus fields of the proposal header
// h (a skeleton with ParentHash, Number, the execution fields and the
// builder vanity): coinbase, time, randao, the previous seals and the gas
// tip. It waits for the authority snapshot of the parent if the cache does
// not have it.
func (s *service) PrepareConsensusFields(ctx context.Context, h *types.Header) (*types.Header, error) {
	view, signer, err := s.ready()
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, app.ErrNoSigner
	}
	parent := view.a.HeaderByHash(h.ParentHash)
	if parent == nil {
		return nil, fmt.Errorf("node: parent %x of the proposal is unknown", h.ParentHash)
	}
	snap, err := s.snapshot(ctx, codec.BlockHash(parent))
	if err != nil {
		return nil, err
	}
	var ep, ec []types.SealEntry
	if r := s.n.Runner(); r != nil {
		ep, ec = r.Snapshot().ExtraSeals(parent)
	}
	return header.PrepareProposal(view.env(), h, header.ProposalInputs{Coinbase: signer.Address(),
		Signer: randaoSigner{signer, view.cfg.ChainID, h.Number}, ExtraPrepared: ep, ExtraCommitted: ec,
		ParentGasTip: snap.GasTip()})
}

// snapshot returns the authority snapshot of a block from the cache or the
// application.
func (s *service) snapshot(ctx context.Context, hash types.Hash) (*source.AuthoritySnapshot, error) {
	if snap, ok := s.n.snaps.Get(hash); ok {
		return snap, nil
	}
	snap, err := s.n.d.Authority.Snapshot(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("node: authority snapshot of %x: %w", hash, err)
	}
	s.n.snaps.Put(snap)
	return snap, nil
}

// randaoSigner signs the randao reveal of one block number.
type randaoSigner struct {
	s       *privval.FileSigner
	chainID *big.Int
	number  types.Height
}

func (r randaoSigner) SignRandao([]byte) ([]byte, error) { return r.s.SignRandao(r.chainID, r.number) }

// EpochInfo computes the EpochInfo of epoch block h whose execution is in
// progress in ctx; it returns nil for a block that is not an epoch block.
func (s *service) EpochInfo(ctx context.Context, h *types.Header) (*types.EpochInfo, error) {
	view, _, err := s.ready()
	if err != nil {
		return nil, err
	}
	cands, err := s.n.d.Authority.CandidatesAfterExecution(ctx)
	if err != nil {
		return nil, err
	}
	return epoch.ComputeNextEpochInfo(view.a, view.cfg, h, cands)
}

// VerifyEpochInfo recomputes the EpochInfo of an imported epoch block and
// compares it with the one the block carries.
func (s *service) VerifyEpochInfo(ctx context.Context, h *types.Header) error {
	view, _, err := s.ready()
	if err != nil {
		return err
	}
	cands, err := s.n.d.Authority.CandidatesAfterExecution(ctx)
	if err != nil {
		return err
	}
	return epoch.VerifyEpochInfo(view.a, view.cfg, h, cands)
}

// SubmitProposal hands a built block to the core.
func (s *service) SubmitProposal(b *types.Block) {
	if !s.n.running() {
		return
	}
	if r := s.n.Runner(); r != nil {
		r.Submit(b)
	}
}

// VerifyHeader verifies a header on the import path.
func (s *service) VerifyHeader(_ context.Context, h *types.Header, opt app.VerifyOptions) error {
	view, _, err := s.ready()
	if err != nil {
		return err
	}
	return header.VerifyHeader(view.env(), h, nil, header.Options{CheckSeals: opt.CheckSeals, Mode: header.HeaderOnly})
}

// VerifyHeaders verifies a batch of headers.
func (s *service) VerifyHeaders(ctx context.Context, hs []*types.Header, opt app.VerifyOptions) <-chan error {
	view, _, err := s.ready()
	if err != nil {
		out := make(chan error, len(hs))
		for range hs {
			out <- err
		}
		close(out)
		return out
	}
	return header.VerifyHeaders(ctx, view.env(), hs, header.Options{CheckSeals: opt.CheckSeals, Mode: header.HeaderOnly})
}

// OnBlockExecuted stores the authority snapshot of an executed block.
func (s *service) OnBlockExecuted(snap *source.AuthoritySnapshot) {
	if snap != nil && s.n.running() {
		s.n.snaps.Put(snap)
	}
}

// OnNewHead passes a new head to the core.
func (s *service) OnNewHead(ev app.NewHead) {
	if ev.Header == nil || !s.n.running() {
		return
	}
	s.n.emit(event.Record{Kind: event.NewHead, Fields: map[string]any{"number": ev.Header.Number.String(),
		"hash": "0x" + hex.EncodeToString(codec.BlockHash(ev.Header).Bytes()), "path": ev.Path.String()}})
	if r := s.n.Runner(); r != nil {
		r.NewHead(ev.Header)
	}
}

// OnSyncState records the synchronisation state; the node's sync loop
// stops or starts the core.
func (s *service) OnSyncState(st app.SyncState) {
	if !s.n.running() {
		return
	}
	s.n.syncMu.Lock()
	s.n.syncLatest = &st
	s.n.syncMu.Unlock()
	select {
	case s.n.syncWake <- struct{}{}:
	default:
	}
}

// OnImportFailed records an import failure.
func (s *service) OnImportFailed(f app.ImportFailure) {
	if !s.n.running() {
		return
	}
	fields := map[string]any{"number": f.Number.String(), "hash": "0x" + hex.EncodeToString(f.Hash.Bytes()),
		"path": f.Path.String(), "recorded_bad": f.RecordedBad}
	if f.Err != nil {
		fields["step"], fields["class"] = f.Err.Step, f.Err.Class
	}
	s.n.emit(event.Record{Kind: event.ImportFail, Fields: fields})
}
