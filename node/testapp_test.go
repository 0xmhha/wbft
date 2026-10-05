package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

const testChainID = 8282

// testKey returns the node key i of the tests (never a key of a real
// network).
func testKey(i int) []byte {
	return keccak.Sum256Bytes([]byte("wbft-node-test-key-" + string(rune('a'+i))))
}

// testGenesis returns the chain configuration and block 0 of a chain whose
// genesis validators are the given keys.
func testGenesis(t *testing.T, keys ...[]byte) ([]byte, *types.Block) {
	t.Helper()
	var addrs, blsKeys []string
	for _, k := range keys {
		pk, err := ecdsa.PrivateKeyFromBytes(k)
		if err != nil {
			t.Fatal(err)
		}
		sk, err := bls.DeriveSecretKey(k)
		if err != nil {
			t.Fatal(err)
		}
		a := ecdsa.Address(pk)
		addrs = append(addrs, "0x"+hex.EncodeToString(a[:]))
		blsKeys = append(blsKeys, "0x"+hex.EncodeToString(sk.PublicKey().Bytes()))
	}
	pol := uint64(0)
	cj, err := json.Marshal(map[string]any{"chainId": testChainID, "anzeon": map[string]any{
		"wbft": map[string]any{"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": uint64(1) << 40, "proposerPolicy": &pol},
		"init": map[string]any{"validators": addrs, "blsPublicKeys": blsKeys}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := types.ParseChainConfig(cj)
	if err != nil {
		t.Fatal(err)
	}
	ei, err := epoch.InitialEpochInfo(cfg.Init)
	if err != nil {
		t.Fatal(err)
	}
	g := &types.Header{UncleHash: types.EmptyUncleHash, Root: keccak.Sum256([]byte("wbft-node-test-genesis")), Difficulty: big.NewInt(1),
		Number: types.HeightFromUint64(0), GasLimit: 30_000_000, Time: uint64(time.Now().Unix()) - 1, BaseFee: big.NewInt(1)}
	if err := codec.SetExtra(g, &types.WBFTExtra{GasTip: new(big.Int).SetUint64(types.InitialGasTip), EpochInfo: ei}); err != nil {
		t.Fatal(err)
	}
	return cj, &types.Block{Header: g, Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

// testApp is an application on an in-memory chain. It builds empty blocks
// through the node's Consensus service and implements the authority source
// with the gas tip of the genesis for every block.
type testApp struct {
	cfgJSON []byte
	appImps []string // Info.AppImprovements
	genesis *types.Block
	cons    app.Consensus // set before the node starts

	mu     sync.Mutex
	byNum  map[uint64]*types.Block
	byHash map[types.Hash]*types.Block
	head   *types.Block
	heads  chan uint64 // receives the number of every new head
	// noSnapshot makes FinalizeBlock announce a head without passing its
	// authority snapshot (an application that breaks app-interface.md 8.3).
	noSnapshot atomic.Bool
}

func newTestApp(cfgJSON []byte, g *types.Block) *testApp {
	a := &testApp{cfgJSON: cfgJSON, genesis: g, byNum: map[uint64]*types.Block{}, byHash: map[types.Hash]*types.Block{},
		heads: make(chan uint64, 1024)}
	a.insert(g)
	return a
}

func (a *testApp) insert(b *types.Block) {
	a.byNum[b.Header.Number.RefLow64()] = b //wbft:low64 HH-60
	a.byHash[codec.BlockHash(b.Header)] = b
	a.head = b
}

func (a *testApp) Head() *types.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.head.Header
}

func (a *testApp) HeaderByNumber(idx uint64) *types.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b := a.byNum[idx]; b != nil {
		return b.Header
	}
	return nil
}

func (a *testApp) Header(hash types.Hash, idx uint64) *types.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b := a.byHash[hash]; b != nil && b.Header.Number.RefLow64() == idx { //wbft:low64 HH-61
		return b.Header
	}
	return nil
}

func (a *testApp) HeaderByHash(hash types.Hash) *types.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b := a.byHash[hash]; b != nil {
		return b.Header
	}
	return nil
}

func (a *testApp) HasBlock(hash types.Hash, idx uint64) bool { return a.Header(hash, idx) != nil }

func (a *testApp) Info(context.Context) (app.InfoResponse, error) {
	return app.InfoResponse{AppMajors: []uint32{app.Major}, ChainID: big.NewInt(testChainID),
		GenesisHash: codec.BlockHash(a.genesis.Header), ChainConfigJSON: a.cfgJSON, AppImprovements: a.appImps, Head: a.Head()}, nil
}

func (a *testApp) IsBadBlock(types.Hash) bool { return false }

func (a *testApp) VerifyPartB(string, *types.Header, *types.Header, types.BodyRaw) error { return nil }

// ReadyToBuild builds an empty block on the head after the wait.
func (a *testApp) ReadyToBuild(req app.BuildRequest) {
	go func() {
		select {
		case <-time.After(req.Wait):
		case <-req.Done:
			return
		}
		head := a.Head()
		if head.Number.AddUint64(1).Cmp(req.Height) != 0 {
			return
		}
		skel := &types.Header{ParentHash: codec.BlockHash(head), UncleHash: types.EmptyUncleHash, Number: req.Height,
			Root: head.Root, GasLimit: head.GasLimit, BaseFee: head.BaseFee, Extra: []byte("wbft-test")}
		h, err := a.cons.PrepareConsensusFields(context.Background(), skel)
		if err != nil {
			return
		}
		a.cons.SubmitProposal(&types.Block{Header: h, Body: types.BodyRaw{{0xc0}, {0xc0}}})
	}()
}

// FinalizeBlock stores a decided block that extends the head.
func (a *testApp) FinalizeBlock(_ context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	hash := codec.BlockHash(req.Block.Header)
	a.mu.Lock()
	if codec.BlockHash(a.head.Header) == hash {
		a.mu.Unlock()
		return app.FinalizeResponse{Hash: hash, AlreadyHead: true}, nil
	}
	if req.Block.Header.ParentHash != codec.BlockHash(a.head.Header) {
		a.mu.Unlock()
		return app.FinalizeResponse{}, app.ErrConflictingBlock
	}
	a.insert(req.Block)
	a.mu.Unlock()
	if s, err := a.Snapshot(context.Background(), hash); err == nil && !a.noSnapshot.Load() {
		a.cons.OnBlockExecuted(s)
	}
	a.cons.OnNewHead(app.NewHead{Header: req.Block.Header, Path: app.SealedLocally})
	a.heads <- req.Block.Header.Number.RefLow64() //wbft:low64 HH-60
	return app.FinalizeResponse{Hash: hash}, nil
}

// CandidatesAfterExecution returns the genesis validators.
func (a *testApp) CandidatesAfterExecution(context.Context) ([]types.CandidateEntry, error) {
	cfg, err := types.ParseChainConfig(a.cfgJSON)
	if err != nil {
		return nil, err
	}
	var out []types.CandidateEntry
	for i, v := range cfg.Init.Validators {
		out = append(out, types.CandidateEntry{Addr: v, BLSPublicKey: cfg.Init.BLSPublicKeys[i]})
	}
	return out, nil
}

// Snapshot returns the authority snapshot of a stored block.
func (a *testApp) Snapshot(_ context.Context, hash types.Hash) (*source.AuthoritySnapshot, error) {
	h := a.HeaderByHash(hash)
	if h == nil {
		return nil, app.ErrStateUnavailable
	}
	tip, err := source.GasTipFromBig(new(big.Int).SetUint64(types.InitialGasTip))
	if err != nil {
		return nil, err
	}
	return source.NewAuthoritySnapshot(h.Number, hash, tip, nil, nil, nil)
}

// waitHead waits until the head reaches n.
func (a *testApp) waitHead(t *testing.T, n uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if a.Head().Number.CmpUint64(n) >= 0 {
			return
		}
		select {
		case <-a.heads:
		case <-deadline:
			t.Fatalf("head %s did not reach %d in %v", a.Head().Number, n, timeout)
		}
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers and readers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitEvent waits until the event stream contains substr.
func waitEvent(t *testing.T, ev *syncBuffer, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(ev.String(), substr) {
		if time.Now().After(deadline) {
			t.Fatalf("no event with %q in %v", substr, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// block returns the stored block of a number.
func (a *testApp) block(n uint64) *types.Block {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byNum[n]
}
