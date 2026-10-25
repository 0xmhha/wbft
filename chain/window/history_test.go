package window_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

// The application's existing interface is exercised without permitting any
// lookup that truncates a height or substitutes a canonical same-height view.
type hashStore struct {
	headers map[types.Hash]*types.Header
	reads   []types.Hash
}

func (s *hashStore) HeaderByHash(hash types.Hash) *types.Header {
	s.reads = append(s.reads, hash)
	return s.headers[hash]
}
func (*hashStore) Head() *types.Header                     { panic("unexpected canonical head lookup") }
func (*hashStore) HeaderByNumber(uint64) *types.Header     { panic("unexpected low-width lookup") }
func (*hashStore) Header(types.Hash, uint64) *types.Header { panic("unexpected low-width lookup") }
func (*hashStore) HasBlock(types.Hash, uint64) bool        { panic("unexpected low-width lookup") }
func consensusConfig() *types.Config {
	return types.NewConfig(types.WBFTParams{EpochLength: 6}, nil, types.GenesisInit{}, big.NewInt(88001))
}

func TestBranchHistoryNormalEpochAndCombinedApply(t *testing.T) {
	c := normalScenario(t, 4, types.HeightFromUint64(1), true)
	store := &hashStore{headers: c.history.headers}
	cfg := consensusConfig()
	provider, err := state.NewBranchHistory(c.engine, store, cfg, 6)
	must(t, err)
	cfg.ChainID.SetUint64(999)
	for n := 1; n <= 24; n++ {
		h := c.headers[n]
		before := len(store.reads)
		got, err := provider.Authority(h)
		must(t, err)
		if len(store.reads)-before > 6 {
			t.Fatal("unbounded historical walk")
		}
		want := members(t, n)
		if len(got) != len(want) {
			t.Fatal("historical member count")
		}
		for i, m := range got {
			if m.Address != want[i].Address || !bytes.Equal(m.Key, want[i].Key) {
				t.Fatalf("historical signer order/key at %d", n)
			}
		}
		next, err := c.engine.VerifyAndApply(c.states[n-1], h, provider)
		must(t, err)
		a, err := c.engine.Root(next)
		must(t, err)
		b, err := c.engine.Root(c.states[n])
		must(t, err)
		if a != b {
			t.Fatal("combined verifier changed observation state")
		}
		// Returned slices and headers belong to the caller.
		got[0].Key[0] ^= 1
		again, err := provider.Authority(h)
		must(t, err)
		if !bytes.Equal(again[0].Key, want[0].Key) {
			t.Fatal("authority alias")
		}
		hash, err := c.history.hash(h)
		must(t, err)
		copyHeader, err := provider.Header(hash, h.Number)
		must(t, err)
		copyHeader.Extra[0] ^= 1
		_, err = provider.Header(hash, h.Number)
		must(t, err)
	}
}

func TestBranchHistoryBudgetAndClosedCopies(t *testing.T) {
	c := normalScenario(t, 2, types.HeightFromUint64(1), true)
	store := &hashStore{headers: c.history.headers}
	provider, err := state.NewBranchHistory(c.engine, store, consensusConfig(), 2)
	must(t, err)
	before := len(store.reads)
	if _, err = provider.Authority(c.headers[6]); !errors.Is(err, state.ErrLookupLimit) {
		t.Fatal("walk budget", err)
	}
	if len(store.reads) != before {
		t.Fatal("over-budget walk started")
	}
	provider, err = state.NewBranchHistory(c.engine, store, consensusConfig(), 6)
	must(t, err)
	h := c.headers[7]
	hash, err := c.history.hash(h)
	must(t, err)
	if _, err = provider.Header(hash, h.Number.AddUint64(1)); !errors.Is(err, state.ErrHistory) {
		t.Fatal("full height not checked", err)
	}
	copyHeader := h.Copy()
	copyHeader.ParentHash[0] ^= 1
	if _, err = provider.Authority(copyHeader); !errors.Is(err, state.ErrHistory) {
		t.Fatal("missing branch", err)
	}
	x, err := wire.Decode(h.Extra, c.history.limits)
	must(t, err)
	x.Legacy.PreparedSeal = nil
	copyHeader = h.Copy()
	copyHeader.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	parent := c.states[6]
	root, err := c.engine.Root(parent)
	must(t, err)
	if _, err = c.engine.VerifyAndApply(parent, copyHeader, provider); !errors.Is(err, state.ErrFinality) {
		t.Fatal("missing current certificate", err)
	}
	x, err = wire.Decode(h.Extra, c.history.limits)
	must(t, err)
	x.Legacy.PrevCommittedSeal = nil
	copyHeader.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	if _, err = c.engine.VerifyAndApply(parent, copyHeader, provider); !errors.Is(err, state.ErrFinality) {
		t.Fatal("missing parent certificate", err)
	}
	after, err := c.engine.Root(parent)
	must(t, err)
	if root != after {
		t.Fatal("certificate failure changed parent")
	}
	if _, err = state.NewBranchHistory(c.engine, store, consensusConfig(), 0); err == nil {
		t.Fatal("implicit lookup budget")
	}
}

func TestFinalityMinimumQuorumKeepsSubsetObservationsSeparate(t *testing.T) {
	c := normalScenario(t, 4, types.HeightFromUint64(1), true)
	provider, err := state.NewBranchHistory(c.engine, &hashStore{headers: c.history.headers}, consensusConfig(), 6)
	must(t, err)
	h := c.headers[24].Copy()
	x, err := wire.Decode(h.Extra, c.history.limits)
	must(t, err)
	for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
		bitmap, sig := aggregate(t, h, x.Legacy.Round, phase, members(t, 24), c.history.limits, func(i int) bool { return i < 3 })
		certificate := &types.AggregatedSeal{Sealers: bitmap, Signature: sig}
		if phase == types.PrepareSeal {
			x.Legacy.PreparedSeal = certificate
		} else {
			x.Legacy.CommittedSeal = certificate
		}
	}
	h.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	_, err = c.engine.VerifyAndApply(c.states[23], h, provider)
	must(t, err)
	// Diagnose only a closed metadata copy, without creating or sending a vote.
	x.Legacy.PreparedSeal.Sealers = types.SealerSet{1}
	h.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	if _, err = c.engine.VerifyAndApply(c.states[23], h, provider); !errors.Is(err, state.ErrFinality) {
		t.Fatal("observation subset used as finality", err)
	}
}

func TestBranchHistoryFullHeightEpochTransition(t *testing.T) {
	limits := wire.Limits{ExtraBytes: 65536, Proofs: 16, SettlementRows: 16, Validators: 8}
	raw, err := codec.EncodeExtra(&types.WBFTExtra{EpochInfo: epochInfo(members(t, 1))})
	must(t, err)
	genesis := &types.Header{Difficulty: big.NewInt(1), Extra: raw}
	genesisHash := codec.BlockHash(genesis)
	anchorNumber := new(big.Int).Lsh(big.NewInt(1), 128)
	anchor := genesis.Copy()
	anchor.Number = types.MustHeightFromBig(anchorNumber)
	anchor.ParentHash = genesisHash
	anchorHash := codec.BlockHash(anchor)
	activation := anchor.Number.AddUint64(1)
	engine, err := state.New(state.Config{ChainID: big.NewInt(88001), GenesisHash: genesisHash, Activation: activation, Window: 4, Codec: limits, StateBytes: 65536, CheckpointBytes: 131072, AddressRows: 16})
	must(t, err)
	store := &hashStore{headers: map[types.Hash]*types.Header{genesisHash: genesis, anchorHash: anchor}}
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 6}, []types.Transition{{Block: anchorNumber, WBFT: &types.WBFTParams{EpochLength: 8}}}, types.GenesisInit{}, big.NewInt(88001))
	provider, err := state.NewBranchHistory(engine, store, cfg, 1)
	must(t, err)
	candidate := &types.Header{Number: activation, ParentHash: anchorHash}
	got, err := provider.Authority(candidate)
	must(t, err)
	if len(got) != 4 {
		t.Fatal("full-height epoch authority")
	}
	// A caller-trusted high epoch anchor supplies history here; this fixture
	// does not claim to reconstruct the omitted chain from genesis.
	if _, err = provider.Header(anchorHash, types.HeightFromUint64(0)); err == nil {
		t.Fatal("low64 collision accepted")
	}
	anchorNumber.SetUint64(0)
	got, err = provider.Authority(candidate)
	must(t, err)
	if len(got) != 4 {
		t.Fatal("mutable input transition")
	}
}

func TestFinalityAcrossLegacyActivationBoundary(t *testing.T) {
	limits := wire.Limits{ExtraBytes: 65536, Proofs: 16, SettlementRows: 16, Validators: 8}
	raw, err := codec.EncodeExtra(&types.WBFTExtra{EpochInfo: epochInfo(members(t, 1))})
	must(t, err)
	genesis := &types.Header{Difficulty: big.NewInt(1), Extra: raw}
	genesisHash := codec.BlockHash(genesis)
	raw, err = codec.EncodeExtra(&types.WBFTExtra{})
	must(t, err)
	parent := &types.Header{Number: types.HeightFromUint64(1), ParentHash: genesisHash, Difficulty: big.NewInt(1), Extra: raw}
	x, err := codec.DecodeExtra(parent)
	must(t, err)
	for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
		var signatures [][]byte
		var bitmap types.SealerSet
		for i, m := range members(t, 1) {
			signatures = append(signatures, keyFor(t, m).Sign(codec.SealData(parent, 0, phase)).Bytes())
			bitmap.SetSealer(uint32(i))
		}
		sig, err := bls.AggregateSignatures(signatures)
		must(t, err)
		seal := &types.AggregatedSeal{Sealers: bitmap, Signature: sig.Bytes()}
		if phase == types.PrepareSeal {
			x.PreparedSeal = seal
		} else {
			x.CommittedSeal = seal
		}
	}
	must(t, codec.SetExtra(parent, x))
	parentHash := codec.BlockHash(parent)
	engine, err := state.New(state.Config{ChainID: big.NewInt(88001), GenesisHash: genesisHash, Activation: types.HeightFromUint64(2), Window: 4, Codec: limits, StateBytes: 65536, CheckpointBytes: 131072, AddressRows: 16})
	must(t, err)
	store := &hashStore{headers: map[types.Hash]*types.Header{genesisHash: genesis, parentHash: parent}}
	provider, err := state.NewBranchHistory(engine, store, consensusConfig(), 2)
	must(t, err)
	initialState, err := engine.Initial(parent)
	must(t, err)
	legacy := &types.WBFTExtra{PrevPreparedSeal: x.PreparedSeal.Copy(), PrevCommittedSeal: x.CommittedSeal.Copy()}
	raw, err = codec.EncodeExtra(legacy)
	must(t, err)
	candidate := &types.Header{Number: types.HeightFromUint64(2), ParentHash: parentHash, Difficulty: big.NewInt(1), Extra: raw}
	carrier, built, err := engine.Build(initialState, candidate, nil, provider)
	must(t, err)
	envelope, err := wire.Decode(carrier.Extra, limits)
	must(t, err)
	for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
		bitmap, sig := aggregate(t, carrier, 0, phase, members(t, 2), limits, func(int) bool { return true })
		seal := &types.AggregatedSeal{Sealers: bitmap, Signature: sig}
		if phase == types.PrepareSeal {
			envelope.Legacy.PreparedSeal = seal
		} else {
			envelope.Legacy.CommittedSeal = seal
		}
	}
	carrier.Extra, err = wire.Encode(envelope, limits)
	must(t, err)
	applied, err := engine.VerifyAndApply(initialState, carrier, provider)
	must(t, err)
	want, err := engine.Root(built)
	must(t, err)
	got, err := engine.Root(applied)
	must(t, err)
	if got != want {
		t.Fatal("legacy/V2 boundary root")
	}
}
