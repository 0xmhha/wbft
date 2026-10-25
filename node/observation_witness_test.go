package node

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// This is a closed header/witness fixture signed by four owned test keys. No
// node, receiver, network or consensus actor is started or given modified inputs.
func TestOwnedWitnessRoundSurvivesDifferentStoredCertificate(t *testing.T) {
	keys := [][]byte{testKey(0), testKey(1), testKey(2), testKey(3)}
	raw, genesis := testGenesis(t, keys...)
	application := newTestApp(raw, genesis)
	rules, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	option := ObservationConfig{Policy: window.Config{ChainID: rules.ChainID, GenesisHash: codec.BlockHash(genesis.Header), Activation: types.HeightFromUint64(1), Window: 4, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20, CheckpointBytes: 2 << 20, AddressRows: 32}, Retention: types.HeightFromUint64(3), HistoryWalk: 128, ReplayHeaders: 128, WitnessItems: 64, WitnessBytes: 1 << 20, WitnessChecksPerStep: 32}
	engine, err := window.NewRecent(option.Policy, option.Retention)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.Initial(genesis.Header)
	if err != nil {
		t.Fatal(err)
	}
	memory := fsys.NewMem()
	if err := memory.MkdirAll("/witness", 0700); err != nil {
		t.Fatal(err)
	}
	runtime := &observationRuntime{cfg: option, engine: engine, chain: application, rules: rules, fs: memory, dir: "/witness", state: initial, anchor: codec.BlockHash(genesis.Header)}
	private, err := ecdsa.PrivateKeyFromBytes(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	environment := &header.Env{Config: rules, Chain: application, Now: time.Now, Observation: runtime}
	build := func(parent *types.Header) *types.Header {
		t.Helper()
		parentState, err := application.Snapshot(context.Background(), codec.BlockHash(parent))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := header.PrepareProposal(environment, &types.Header{Number: parent.Number.AddUint64(1), ParentHash: codec.BlockHash(parent), Root: parent.Root, TxHash: parent.TxHash, UncleHash: types.EmptyUncleHash, GasLimit: parent.GasLimit, BaseFee: parent.BaseFee, Extra: []byte("owned-witness")}, header.ProposalInputs{Coinbase: ecdsa.Address(private), Signer: futureHeaderSigner{private}, ParentGasTip: parentState.GasTip()})
		if err != nil {
			t.Fatal(err)
		}
		return candidate
	}
	seal := func(h *types.Header, round uint32, phase types.SealType, index int) []byte {
		t.Helper()
		key, err := bls.DeriveSecretKey(keys[index])
		if err != nil {
			t.Fatal(err)
		}
		return key.Sign(codec.SealData(h, round, phase)).Bytes()
	}
	entries := func(h *types.Header, round uint32, phase types.SealType) []types.SealEntry {
		t.Helper()
		var result []types.SealEntry
		for index := uint32(0); index < 3; index++ {
			result = append(result, types.SealEntry{Sealer: index, Seal: seal(h, round, phase, int(index))})
		}
		return result
	}
	history, err := runtime.history(application)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := engine.Build(initial, build(genesis.Header), nil, history)
	if err != nil {
		t.Fatal(err)
	}
	certified, err := header.CommitHeader(&types.Block{Header: first, Body: genesis.Body}, types.RoundFromUint64(0), entries(first, 0, types.PrepareSeal), entries(first, 0, types.CommitSeal))
	if err != nil {
		t.Fatal(err)
	}
	if err := header.VerifyHeader(environment, certified.Header, nil, header.Options{CheckSeals: true, Mode: header.HeaderOnly}); err != nil {
		t.Fatal(err)
	}
	application.insert(certified)
	if err := runtime.adopt(certified.Header); err != nil {
		t.Fatal(err)
	}
	fourth, err := ecdsa.PrivateKeyFromBytes(keys[3])
	if err != nil {
		t.Fatal(err)
	}
	source := ecdsa.Address(fourth)
	extra := consensus.ExtraSealEntry{Source: source, View: types.View{Sequence: first.Number, Round: types.RoundFromUint64(3)}, Digest: codec.BlockHash(first), Seal: seal(first, 3, types.PrepareSeal, 3)}
	runtime.observeSeals([]consensus.ExtraSealEntry{extra}, nil)
	if len(runtime.witnesses) != 1 || runtime.witnesses[0].Round != 3 {
		t.Fatalf("valid round-3 witness excluded by stored round-0 certificate: %d", len(runtime.witnesses))
	}
	// A full verified view uses the same existing uint32 BLS signing domain.
	alias := extra
	aliasRound, err := types.RoundFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(3)))
	if err != nil {
		t.Fatal(err)
	}
	alias.View.Round = aliasRound
	runtime.observeSeals([]consensus.ExtraSealEntry{alias}, nil)
	if len(runtime.witnesses) != 1 {
		t.Fatal("same signer and signing domain counted twice")
	}
	// Keep a second valid signing round, then select only the successor-bound
	// final round. The fourth individual must not overlap the intact quorum.
	other := extra
	other.View.Round = types.RoundFromUint64(0)
	other.Seal = seal(first, 0, types.PrepareSeal, 3)
	runtime.observeSeals([]consensus.ExtraSealEntry{other}, nil)
	if len(runtime.witnesses) != 2 {
		t.Fatal("distinct valid signing round was lost")
	}
	second := build(certified.Header)
	legacy, err := codec.DecodeExtra(second)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := func(phase types.SealType) *types.AggregatedSeal {
		t.Helper()
		var signatures [][]byte
		var bitmap types.SealerSet
		for index := uint32(0); index < 3; index++ {
			signatures = append(signatures, seal(first, 3, phase, int(index)))
			bitmap.SetSealer(index)
		}
		signature, err := bls.AggregateSignatures(signatures)
		if err != nil {
			t.Fatal(err)
		}
		return &types.AggregatedSeal{Sealers: bitmap, Signature: signature.Bytes()}
	}
	legacy.PrevRound = 3
	legacy.PrevPreparedSeal = aggregate(types.PrepareSeal)
	legacy.PrevCommittedSeal = aggregate(types.CommitSeal)
	if err := codec.SetExtra(second, legacy); err != nil {
		t.Fatal(err)
	}
	proofs, err := runtime.selectProofs(second, legacy, history)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 2 || len(types.SealerSet(proofs[0].Bitmap).Sealers()) != 4 || len(types.SealerSet(proofs[1].Bitmap).Sealers()) != 3 {
		t.Fatal("verified witness was lost or overlapped the quorum")
	}
	carrier, _, err := engine.Build(runtime.state, second, proofs, history)
	if err != nil {
		t.Fatal(err)
	}
	for uint64(time.Now().Unix()) < carrier.Time {
		time.Sleep(10 * time.Millisecond)
	}
	if err := header.VerifyHeader(environment, carrier, nil, header.Options{CheckSeals: false, Mode: header.HeaderOnly}); err != nil {
		t.Fatal(err)
	}
	// Confirm this helper did not construct or run a consensus service.
	if application.cons != nil {
		t.Fatal("closed fixture unexpectedly bound a service")
	}
}
