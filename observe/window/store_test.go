package window_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	store "github.com/0xmhha/wbft/observe/window"
	"github.com/0xmhha/wbft/types"
)

type bootstrapHistory struct{ parent *types.Header }

func (h bootstrapHistory) Header(hash types.Hash, n types.Height) (*types.Header, error) {
	if codec.BlockHash(h.parent) != hash || h.parent.Number.Cmp(n) != 0 {
		return nil, state.ErrHistory
	}
	return h.parent.Copy(), nil
}
func (bootstrapHistory) Authority(*types.Header) ([]wire.Member, error) { return nil, state.ErrHistory }

func fixture(t *testing.T) (*state.Engine, *state.State, *types.Header) {
	t.Helper()
	raw, err := codec.EncodeExtra(&types.WBFTExtra{VanityData: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	parent := &types.Header{Difficulty: big.NewInt(1), Extra: raw}
	engine, err := state.New(state.Config{ChainID: big.NewInt(17), GenesisHash: codec.BlockHash(parent), Activation: types.HeightFromUint64(1), Window: 4, Codec: wire.Limits{ExtraBytes: 4096, Proofs: 8, SettlementRows: 8, Validators: 8}, StateBytes: 4096, CheckpointBytes: 4096, AddressRows: 8})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.Initial(parent)
	if err != nil {
		t.Fatal(err)
	}
	candidate := parent.Copy()
	candidate.Number = types.HeightFromUint64(1)
	candidate.ParentHash = codec.BlockHash(parent)
	h, s, err := engine.Build(initial, candidate, nil, bootstrapHistory{parent})
	if err != nil {
		t.Fatal(err)
	}
	return engine, s, h
}

func TestOwnedCheckpointSaveReopenAndAnchor(t *testing.T) {
	e, s, h := fixture(t)
	path := filepath.Join(t.TempDir(), "observation.rlp")
	for i := 0; i < 2; i++ {
		if err := store.Save(path, e, s, h); err != nil {
			t.Fatal(err)
		}
		restored, err := store.Load(path, e, h)
		if err != nil {
			t.Fatal(err)
		}
		want, err := e.Root(s)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Root(restored)
		if err != nil || got != want {
			t.Fatal("checkpoint root", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary file left behind", err)
	}
	other := h.Copy()
	other.ParentHash[0] ^= 1
	if _, err = store.Load(path, e, other); err == nil {
		t.Fatal("untrusted anchor accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("checkpoint permissions")
	}
}

func TestClosedCheckpointReadBoundAndCanonicalEncoding(t *testing.T) {
	e, s, h := fixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "original.rlp")
	if err := store.Save(path, e, s, h); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "copied.rlp")
	if err = os.WriteFile(copied, append(append([]byte(nil), raw...), 0), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(copied, e, h); err == nil {
		t.Fatal("noncanonical closed copy")
	}
	if err = os.WriteFile(copied, make([]byte, e.CheckpointLimit()+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(copied, e, h); err == nil {
		t.Fatal("unbounded read")
	}
	if _, err = store.Load(path, nil, h); err == nil {
		t.Fatal("missing policy")
	}
	if err = store.Save(filepath.Join(dir, "missing", "state.rlp"), e, s, h); err == nil {
		t.Fatal("unexpected directory ownership")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != string(raw) {
		t.Fatal("original checkpoint changed", err)
	}
}
