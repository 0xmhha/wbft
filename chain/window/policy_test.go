package window_test

import (
	"math/big"
	"testing"

	state "github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
)

func TestPolicyIdentityIncludesCapacityAndOwnsInputs(t *testing.T) {
	cfg := state.Config{ChainID: big.NewInt(17), GenesisHash: types.Hash{1}, Activation: types.HeightFromUint64(3), Window: 4, Codec: wire.Limits{ExtraBytes: 4096, Proofs: 8, SettlementRows: 8, Validators: 8}, StateBytes: 4096, CheckpointBytes: 8192, AddressRows: 8}
	e, err := state.New(cfg)
	must(t, err)
	digest := e.Digest()
	cfg.ChainID.SetUint64(18)
	if e.Digest() != digest {
		t.Fatal("mutable policy identity")
	}
	other, err := state.New(cfg)
	must(t, err)
	if other.Digest() == digest {
		t.Fatal("chain identity not bound")
	}
	cfg.ChainID = big.NewInt(17)
	cfg.Codec.Validators++
	other, err = state.New(cfg)
	must(t, err)
	if other.Digest() == digest {
		t.Fatal("signer limit not bound")
	}
	cfg.Codec.Validators--
	cfg.CheckpointBytes++
	other, err = state.New(cfg)
	must(t, err)
	if other.Digest() == digest {
		t.Fatal("checkpoint limit not bound")
	}
	if _, err = state.New(state.Config{}); err == nil {
		t.Fatal("implicit defaults")
	}
	cfg.GenesisHash = types.Hash{}
	if _, err = state.New(cfg); err == nil {
		t.Fatal("missing genesis identity")
	}
}
