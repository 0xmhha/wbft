package kvstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/types"
)

// keepStates is the number of recent block states kept for proposal
// verification besides the head state.
const keepStates = 64

// App is the kvstore application. It implements app.Application,
// source.AuthoritySource and, through Admission, mempool.AdmissionHook.
type App struct {
	log      *slog.Logger
	cfgJSON  []byte
	chainCfg *types.Config
	genesis  *types.Block
	store    *store

	mu     sync.Mutex // serialises storing blocks
	states map[types.Hash]*State
	order  []types.Hash // state keys, oldest first

	wiring sync.RWMutex
	cons   app.Consensus
	pool   mempool.Pool
	peers  Peers
}

// Peers is the application's view of the network: block announcement and
// synchronisation. Package-level helpers implement it on p2p/devnet.
type Peers interface {
	// AnnounceBlock sends a new block to every peer.
	AnnounceBlock(b *types.Block)
	// RequestBlocks asks peer for the blocks from number from.
	RequestBlocks(peer types.Address, from uint64)
}

var (
	_ app.Application        = (*App)(nil)
	_ source.AuthoritySource = (*App)(nil)
)

// Open opens the application state in dir with the genesis g: it loads the
// stored blocks and executes them again to rebuild the state.
func Open(dir string, g *Genesis, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	gb, err := g.block()
	if err != nil {
		return nil, fmt.Errorf("kvstore: genesis block: %w", err)
	}
	cfg, err := types.ParseChainConfig(g.Config)
	if err != nil {
		return nil, err
	}
	st, err := openStore(dir, gb)
	if err != nil {
		return nil, err
	}
	a := &App{log: log, cfgJSON: g.Config, chainCfg: cfg, genesis: gb, store: st, states: map[types.Hash]*State{}}
	state := emptyState()
	a.putState(codec.BlockHash(gb.Header), state)
	for _, b := range st.blocks()[1:] {
		next, _, err := execBlock(state, b)
		if err != nil {
			return nil, fmt.Errorf("kvstore: stored block %v: %w", b.Header.Number, err)
		}
		state = next
		a.putState(codec.BlockHash(b.Header), state)
	}
	return a, nil
}

// Attach connects the application to the node's Consensus service, the
// transaction pool (nil when none) and the network (nil when none). It is
// called before the node starts; the pool is known only after the start
// and is attached with SetPool.
func (a *App) Attach(c app.Consensus, peers Peers) {
	a.wiring.Lock()
	defer a.wiring.Unlock()
	a.cons, a.peers = c, peers
}

// SetPool attaches the transaction pool.
func (a *App) SetPool(p mempool.Pool) {
	a.wiring.Lock()
	defer a.wiring.Unlock()
	a.pool = p
}

func (a *App) wired() (app.Consensus, mempool.Pool, Peers) {
	a.wiring.RLock()
	defer a.wiring.RUnlock()
	return a.cons, a.pool, a.peers
}

// Admission returns the admission hook of the transaction pool.
func (a *App) Admission() mempool.AdmissionHook { return admission{a} }

func (a *App) putState(h types.Hash, s *State) {
	a.states[h] = s
	a.order = append(a.order, h)
	head := codec.BlockHash(a.store.Head())
	for len(a.order) > keepStates {
		if a.order[0] != head {
			delete(a.states, a.order[0])
		}
		a.order = a.order[1:]
	}
}

func (a *App) stateOf(h types.Hash) *State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.states[h]
}

func (a *App) headState() *State { return a.stateOf(codec.BlockHash(a.store.Head())) }

// Get returns the value of key in the head state.
func (a *App) Get(key string) (string, bool) { return a.headState().Get(key) }

// Nonce returns the next nonce of a sender in the head state.
func (a *App) Nonce(from types.Address) uint64 { return a.headState().Nonce(from) }

// BlockByNumber returns a stored canonical block.
func (a *App) BlockByNumber(n uint64) *types.Block { return a.store.blockByNumber(n) }

// ---- types.ChainReader

func (a *App) Head() *types.Header                              { return a.store.Head() }
func (a *App) HeaderByNumber(idx uint64) *types.Header          { return a.store.HeaderByNumber(idx) }
func (a *App) Header(hash types.Hash, idx uint64) *types.Header { return a.store.Header(hash, idx) }
func (a *App) HeaderByHash(hash types.Hash) *types.Header       { return a.store.HeaderByHash(hash) }
func (a *App) HasBlock(hash types.Hash, idx uint64) bool        { return a.store.HasBlock(hash, idx) }

// ---- app.Application

// Info implements app.Application.
func (a *App) Info(context.Context) (app.InfoResponse, error) {
	return app.InfoResponse{AppMajors: []uint32{app.Major}, ChainID: new(big.Int).Set(a.chainCfg.ChainID),
		GenesisHash: codec.BlockHash(a.genesis.Header), ChainConfigJSON: a.cfgJSON, Head: a.Head()}, nil
}

// IsBadBlock implements app.Application. The example keeps no bad-block
// record: an invalid block fails verification every time.
func (a *App) IsBadBlock(types.Hash) bool { return false }

// VerifyPartB implements app.Application: P4 checks the body against the
// header's transaction hash, P5 executes the block on its parent state.
func (a *App) VerifyPartB(step string, h, _ *types.Header, body types.BodyRaw) error {
	switch step {
	case "P4":
		_, err := decodeBody(h, body)
		return err
	case "P5":
		parent := a.stateOf(h.ParentHash)
		if parent == nil {
			return nil // unknown parent: step P7 rejects the proposal
		}
		_, _, err := execBlock(parent, &types.Block{Header: h, Body: body})
		return err
	}
	return nil
}

// ReadyToBuild implements app.Application: after the wait it builds a block
// on the head from the pool and submits it.
func (a *App) ReadyToBuild(req app.BuildRequest) {
	go func() {
		select {
		case <-time.After(req.Wait):
		case <-req.Done:
			return
		}
		b, err := a.build(req)
		if err != nil {
			a.log.Debug("no proposal", "height", req.Height, "err", err)
			return
		}
		cons, _, _ := a.wired()
		cons.SubmitProposal(b)
	}()
}

// build assembles a proposal on the head.
func (a *App) build(req app.BuildRequest) (*types.Block, error) {
	cons, pool, _ := a.wired()
	head := a.store.head()
	if head.Header.Number.AddUint64(1).Cmp(req.Height) != 0 {
		return nil, errors.New("the head moved")
	}
	state := a.stateOf(codec.BlockHash(head.Header))
	var txs []Tx
	var raw [][]byte
	if pool != nil {
		it, err := pool.Proposal(context.Background(), mempool.ProposalRequest{})
		if err != nil {
			return nil, err
		}
		cur := state
		for key, b, _, ok := it.Next(); ok; key, b, _, ok = it.Next() {
			t, err := DecodeTx(b)
			if err != nil {
				it.Report(key, mempool.DropSender)
				continue
			}
			next, err := cur.Apply([]Tx{t})
			if err != nil {
				if t.Nonce < cur.Nonce(t.From) {
					it.Report(key, mempool.SkipTx)
				} else {
					it.Report(key, mempool.DropSender)
				}
				continue
			}
			cur = next
			txs, raw = append(txs, t), append(raw, b)
			it.Report(key, mempool.Included)
		}
	}
	after, err := state.Apply(txs)
	if err != nil {
		return nil, err
	}
	body, txHash, err := encodeBody(raw)
	if err != nil {
		return nil, err
	}
	skel := &types.Header{ParentHash: codec.BlockHash(head.Header), UncleHash: types.EmptyUncleHash, Number: req.Height,
		Root: after.Root(), TxHash: txHash, GasLimit: head.Header.GasLimit, BaseFee: head.Header.BaseFee, Extra: []byte("kvstore")}
	ctx := context.Background()
	h, err := cons.PrepareConsensusFields(ctx, skel)
	if err != nil {
		return nil, err
	}
	if isEpoch, err := validator.IsEpochBlock(a.chainCfg, h.Number); err == nil && isEpoch {
		ei, err := cons.EpochInfo(ctx, h)
		if err != nil {
			return nil, err
		}
		x, err := codec.DecodeExtra(h)
		if err != nil {
			return nil, err
		}
		x.EpochInfo = ei
		if err := codec.SetExtra(h, x); err != nil {
			return nil, err
		}
	}
	return &types.Block{Header: h, Body: body}, nil
}

// FinalizeBlock implements app.Application: it executes and stores a
// decided block and reports the new head.
func (a *App) FinalizeBlock(_ context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	hash := codec.BlockHash(req.Block.Header)
	stored, err := a.storeBlock(req.Block)
	if err != nil {
		return app.FinalizeResponse{}, err
	}
	if !stored {
		return app.FinalizeResponse{Hash: hash, AlreadyHead: true}, nil
	}
	a.afterStore(req.Block, app.SealedLocally)
	return app.FinalizeResponse{Hash: hash}, nil
}

// storeBlock executes and stores a block that extends the head. It reports
// false for the block that is already the head.
func (a *App) storeBlock(b *types.Block) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	head := a.store.head()
	hash := codec.BlockHash(b.Header)
	if codec.BlockHash(head.Header) == hash {
		return false, nil
	}
	if b.Header.ParentHash != codec.BlockHash(head.Header) {
		if a.store.HeaderByHash(hash) != nil {
			return false, nil
		}
		return false, app.ErrConflictingBlock
	}
	parent := a.states[b.Header.ParentHash]
	next, _, err := execBlock(parent, b)
	if err != nil {
		return false, fmt.Errorf("%w: %v", app.ErrInvalidBlock, err)
	}
	if err := a.store.append(b); err != nil {
		return false, fmt.Errorf("%w: %v", app.ErrTemporary, err)
	}
	a.putState(hash, next)
	return true, nil
}

// afterStore runs the head change steps of a stored block: the authority
// snapshot, the pool update, the head notification, and the announcement.
func (a *App) afterStore(b *types.Block, path app.HeadPath) {
	cons, pool, peers := a.wired()
	hash := codec.BlockHash(b.Header)
	if s, err := a.snapshot(b.Header); err == nil {
		cons.OnBlockExecuted(s)
	}
	if pool != nil {
		txs, _ := decodeBody(b.Header, b.Body)
		keys := make([]types.Hash, len(txs))
		for i, raw := range txs {
			keys[i] = TxKey(raw)
		}
		_ = pool.Update(context.Background(), mempool.BlockUpdate{Number: b.Header.Number, Hash: hash, Included: keys})
	}
	cons.OnNewHead(app.NewHead{Header: b.Header, Path: path})
	if peers != nil && path == app.SealedLocally {
		peers.AnnounceBlock(b)
	}
}

// ImportBlock imports a block received from a peer: it extends the head,
// or starts a synchronisation from the peer when it is further ahead.
func (a *App) ImportBlock(from types.Address, b *types.Block) error {
	cons, _, peers := a.wired()
	head := a.store.Head()
	switch n := b.Header.Number; {
	case n.Cmp(head.Number) <= 0:
		return nil
	case n.Cmp(head.Number.AddUint64(1)) > 0:
		if peers != nil {
			peers.RequestBlocks(from, head.Number.AddUint64(1).RefLow64()) //wbft:low64 HH-60
		}
		return nil
	}
	ctx := context.Background()
	if err := cons.VerifyHeader(ctx, b.Header, app.VerifyOptions{CheckSeals: true}); err != nil {
		cons.OnImportFailed(app.ImportFailure{Number: b.Header.Number, Hash: codec.BlockHash(b.Header), Path: app.Imported,
			Err: &app.ImportError{Step: "header", Class: "ErrInvalidHeader", Err: err}})
		return err
	}
	if isEpoch, err := validator.IsEpochBlock(a.chainCfg, b.Header.Number); err == nil && isEpoch {
		if err := cons.VerifyEpochInfo(ctx, b.Header); err != nil {
			return err
		}
	}
	stored, err := a.storeBlock(b)
	if err != nil || !stored {
		return err
	}
	a.afterStore(b, app.Imported)
	return nil
}

// ---- source.AuthoritySource

// CandidatesAfterExecution implements source.AuthoritySource: the
// candidates are the genesis validators forever.
func (a *App) CandidatesAfterExecution(context.Context) ([]types.CandidateEntry, error) {
	out := make([]types.CandidateEntry, len(a.chainCfg.Init.Validators))
	for i, v := range a.chainCfg.Init.Validators {
		out[i] = types.CandidateEntry{Addr: v, BLSPublicKey: a.chainCfg.Init.BLSPublicKeys[i]}
	}
	return out, nil
}

// Snapshot implements source.AuthoritySource: every block has the gas tip
// of the genesis and no restrictions.
func (a *App) Snapshot(_ context.Context, hash types.Hash) (*source.AuthoritySnapshot, error) {
	h := a.HeaderByHash(hash)
	if h == nil {
		return nil, app.ErrStateUnavailable
	}
	return a.snapshot(h)
}

func (a *App) snapshot(h *types.Header) (*source.AuthoritySnapshot, error) {
	tip, err := source.GasTipFromBig(new(big.Int).SetUint64(types.InitialGasTip))
	if err != nil {
		return nil, err
	}
	return source.NewAuthoritySnapshot(h.Number, codec.BlockHash(h), tip, nil, nil, nil)
}

// ---- blocks

// encodeBody returns the body of a block with the transactions and its
// transaction hash.
func encodeBody(txs [][]byte) (types.BodyRaw, types.Hash, error) {
	items := make([][]byte, len(txs))
	for i, t := range txs {
		items[i] = rlp.EncodeString(t)
	}
	list := rlp.EncodeList(items...)
	return types.BodyRaw{list, {0xc0}}, keccak.Sum256(list), nil
}

// decodeBody checks the body against the header and returns the encoded
// transactions.
func decodeBody(h *types.Header, body types.BodyRaw) ([][]byte, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("%w: no transaction list", ErrTx)
	}
	if keccak.Sum256(body[0]) != h.TxHash {
		return nil, fmt.Errorf("%w: transaction hash", ErrTx)
	}
	items, err := rlp.ListItems(body[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTx, err)
	}
	out := make([][]byte, len(items))
	for i, it := range items {
		if err := rlp.DecodeStrict(it, &out[i]); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTx, err)
		}
	}
	return out, nil
}

// execBlock executes a block on its parent state and checks the root.
func execBlock(parent *State, b *types.Block) (*State, []Tx, error) {
	if parent == nil {
		return nil, nil, app.ErrStateUnavailable
	}
	raw, err := decodeBody(b.Header, b.Body)
	if err != nil {
		return nil, nil, err
	}
	txs := make([]Tx, len(raw))
	for i, r := range raw {
		if txs[i], err = DecodeTx(r); err != nil {
			return nil, nil, err
		}
	}
	next, err := parent.Apply(txs)
	if err != nil {
		return nil, nil, err
	}
	if next.Root() != b.Header.Root {
		return nil, nil, fmt.Errorf("%w: state root", ErrTx)
	}
	return next, txs, nil
}
