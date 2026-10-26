package node

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// A closed ordinary header chain with an owned signer exercises the real
// observation verifier, adoption and checkpoint recovery. It starts no node,
// receiver or network and makes no claim of executing an application's VM.
func TestObservationBandBackendAdoptedStateAndAvailability(t *testing.T) {
	key := testKey(0)
	raw, g := testGenesis(t, key)
	a := newTestApp(raw, g)
	rules, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	option := ObservationConfig{Policy: window.Config{ChainID: rules.ChainID, GenesisHash: codec.BlockHash(g.Header), Activation: types.HeightFromUint64(1), Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20, CheckpointBytes: 2 << 20, AddressRows: 32}, Retention: types.HeightFromUint64(3), HistoryWalk: 128, ReplayHeaders: 128, WitnessItems: 64, WitnessBytes: 1 << 20, WitnessChecksPerStep: 32}
	engine, err := window.NewRecent(option.Policy, option.Retention)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.Initial(g.Header)
	if err != nil {
		t.Fatal(err)
	}
	fs := fsys.NewMem()
	if err := fs.MkdirAll("/band", 0700); err != nil {
		t.Fatal(err)
	}
	r := &observationRuntime{cfg: option, engine: engine, chain: a, rules: rules, fs: fs, dir: "/band", state: initial, anchor: codec.BlockHash(g.Header)}
	n := &Node{cfg: Config{Observation: &option}, d: Deps{App: a}, state: started, view: &chainView{observation: r}, info: app.InfoResponse{ChainID: rules.ChainID, GenesisHash: codec.BlockHash(g.Header)}}
	private, err := ecdsa.PrivateKeyFromBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	blsKey, err := bls.DeriveSecretKey(key)
	if err != nil {
		t.Fatal(err)
	}
	q := rpc.ObservationBandRequest{Address: ecdsa.Address(private), View: window.RecentView, Minimum: "3", Numerator: "4", Denominator: "5"}
	check := func(status, history string) *rpc.ObservationBandResult {
		t.Helper()
		out, err := (backend{n}).ObservationBand(q)
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != status {
			t.Fatalf("status=%s reason=%s", out.Status, out.Reason)
		}
		if status != "AVAILABLE" {
			if out.Diagnostic != nil || out.VerificationScope != "" {
				t.Fatal("unavailable source emitted diagnostic")
			}
			return out
		}
		if out.VerificationScope != "node_adopted_observation_state" || out.ChainID != rules.ChainID.String() || out.GenesisHash != codec.BlockHash(g.Header).String() || out.Diagnostic.HistoryStatus != history || out.Diagnostic.CarrierHash != codec.BlockHash(a.Head()).String() {
			t.Fatalf("source/history mismatch: %+v", out)
		}
		return out
	}
	check("BEFORE_ACTIVATION", "")
	n.state = stopped
	check("UNAVAILABLE", "")
	n.state = started
	n.cfg.Observation = nil
	check("DISABLED", "")
	n.cfg.Observation = &option
	currentTime := time.Now()
	env := &header.Env{Config: rules, Chain: a, Now: func() time.Time { return currentTime }, Observation: r}
	build := func() *types.Block {
		t.Helper()
		currentTime = currentTime.Add(time.Second)
		parent := a.Head()
		parentState, err := a.Snapshot(context.Background(), codec.BlockHash(parent))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := header.PrepareProposal(env, &types.Header{Number: parent.Number.AddUint64(1), ParentHash: codec.BlockHash(parent), Root: parent.Root, TxHash: parent.TxHash, UncleHash: types.EmptyUncleHash, GasLimit: parent.GasLimit, BaseFee: parent.BaseFee, Extra: []byte("normal-band")}, header.ProposalInputs{Coinbase: q.Address, Signer: futureHeaderSigner{private}, ParentGasTip: parentState.GasTip()})
		if err != nil {
			t.Fatal(err)
		}
		carrier, err := (&service{n: n}).PrepareObservation(context.Background(), candidate)
		if err != nil {
			t.Fatal(err)
		}
		entries := func(phase types.SealType) []types.SealEntry {
			return []types.SealEntry{{Sealer: 0, Seal: blsKey.Sign(codec.SealData(carrier, 0, phase)).Bytes()}}
		}
		certified, err := header.CommitHeader(&types.Block{Header: carrier, Body: g.Body}, types.RoundFromUint64(0), entries(types.PrepareSeal), entries(types.CommitSeal))
		if err != nil {
			t.Fatal(err)
		}
		if err := header.VerifyHeader(env, certified.Header, nil, header.Options{CheckSeals: true, Mode: header.HeaderOnly}); err != nil {
			t.Fatal(err)
		}
		return certified
	}
	for i := 1; i <= 7; i++ {
		block := build()
		a.insert(block)
		if err := r.adopt(block.Header); err != nil {
			t.Fatal(err)
		}
		before, err := engine.EncodeCheckpoint(r.state, block.Header)
		if err != nil {
			t.Fatal(err)
		}
		want := "SUFFICIENT_HISTORY"
		if i <= 2 {
			want = "NO_HISTORY"
		} else if i < 5 {
			want = "INSUFFICIENT_HISTORY"
		}
		out := check("AVAILABLE", want)
		if want == "SUFFICIENT_HISTORY" && (out.Diagnostic.ObservedBand == nil || *out.Diagnostic.ObservedBand != "IN_OBSERVED_BAND") {
			t.Fatal("normal complete observations below threshold")
		}
		q.View = window.SettledView
		settled := check("AVAILABLE", "NO_HISTORY")
		q.View = window.RecentView
		if settled.Diagnostic.View != window.SettledView {
			t.Fatal("settled and recent mixed")
		}
		after, err := engine.EncodeCheckpoint(r.state, block.Header)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("RPC query changed checkpoint", err)
		}
	}
	q.Address = types.Address{99}
	check("AVAILABLE", "NO_HISTORY")
	q.Address = ecdsa.Address(private)
	reopened := &observationRuntime{cfg: option, engine: engine, chain: a, rules: rules, fs: fs, dir: "/band"}
	if err := reopened.recover(); err != nil {
		t.Fatal(err)
	}
	n.view.observation = reopened
	r = reopened
	env.Observation = r
	check("AVAILABLE", "SUFFICIENT_HISTORY")
	r.unavailable = errors.New("closed fixture unavailable")
	check("UNAVAILABLE", "")
	r.unavailable = nil
	block := build()
	a.insert(block)
	if got := check("UNAVAILABLE", ""); got.Reason != "observation_tip_not_current" {
		t.Fatal("stale state passed as current", got)
	}
	if err := r.adopt(block.Header); err != nil {
		t.Fatal(err)
	}
	check("AVAILABLE", "SUFFICIENT_HISTORY")
	q.Minimum = "4"
	if _, err := (backend{n}).ObservationBand(q); err == nil {
		t.Fatal("minimum exceeds retained window")
	}
}
