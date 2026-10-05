package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/rejection"
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
	return header.PrepareProposal(view.env(""), h, header.ProposalInputs{Coinbase: signer.Address(),
		Signer: randaoSigner{signer, view.cfg.ChainID, h.Number}, ExtraPrepared: ep, ExtraCommitted: ec,
		ParentGasTip: snap.GasTip()})
}

// snapshot returns the authority snapshot of a block from the cache or the
// application.
func (s *service) snapshot(ctx context.Context, hash types.Hash) (*source.AuthoritySnapshot, error) {
	if snap, ok := s.n.snaps.Get(hash); ok {
		return snap, nil
	}
	s.n.cacheMisses.Inc("build")
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

// VerifyEpochInfo checks the EpochInfo of an imported block after its
// execution: an epoch block's must equal the one recomputed from the
// candidates in the execution state, and any other block must carry none.
// The application calls it for every block (app-interface 8.7).
func (s *service) VerifyEpochInfo(ctx context.Context, h *types.Header) error {
	view, _, err := s.ready()
	if err != nil {
		return err
	}
	isEpoch, err := validator.IsEpochBlock(view.cfg, h.Number)
	if err != nil {
		return err
	}
	if !isEpoch {
		return epoch.CheckNoEpochInfo(h)
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
	return header.VerifyHeader(view.env("header_only"), h, nil, header.Options{CheckSeals: opt.CheckSeals, Mode: header.HeaderOnly})
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
	return header.VerifyHeaders(ctx, view.env("header_only"), hs, header.Options{CheckSeals: opt.CheckSeals, Mode: header.HeaderOnly})
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
	hash := codec.BlockHash(ev.Header)
	s.n.paths.put(hash, ev.Path)
	s.n.emit(event.Record{Kind: event.NewHead, Fields: map[string]any{"number": ev.Header.Number.String(),
		"hash": "0x" + hex.EncodeToString(hash.Bytes()), "path": ev.Path.String()}})
	// The application stores a block's snapshot before it announces the
	// head (app-interface.md 8.3); otherwise the child's PRE-PREPARE finds
	// no parent snapshot.
	if _, ok := s.n.snaps.Get(hash); !ok {
		s.n.emit(event.Record{Kind: event.Health, Fields: map[string]any{"what": "snapshot_missing_at_head",
			"h": ev.Header.Number.String(), "hash": "0x" + hex.EncodeToString(hash.Bytes()), "path": ev.Path.String()}})
	}
	// Before the core hears of the head: the child's round-0 start is the
	// head's time.
	s.n.valMetrics.head(ev.Header)
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
	r := rejection.Record{Number: f.Number.String(), Hash: fields["hash"].(string), Path: f.Path.String(), Time: s.n.clock.Now()}
	if f.Err != nil {
		// "failed_step", not "step": the event writer owns that name (the
		// core step).
		fields["failed_step"], fields["error_class"] = f.Err.Step, f.Err.Class
		r.Step, r.Class = f.Err.Step, f.Err.Class
	}
	s.n.emit(event.Record{Kind: event.ImportFail, Fields: fields})
	s.n.mu.Lock()
	rej := s.n.rej
	s.n.mu.Unlock()
	if rej != nil {
		if err := rej.Add(r); err != nil {
			s.n.log.Warn("rejection store write failed", "err", err)
		}
	}
}
