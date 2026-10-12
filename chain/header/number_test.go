package header

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func numberConfig(t *testing.T, b *builder, at any) *types.Config {
	t.Helper()
	pubs := []string{}
	for _, p := range b.cfg.Init.BLSPublicKeys {
		pubs = append(pubs, "0x"+hex.EncodeToString(p))
	}
	raw, err := json.Marshal(map[string]any{
		"chainId": 8282,
		"anzeon": map[string]any{
			"wbft": map[string]any{"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": 4, "proposerPolicy": 0},
			"init": map[string]any{"validators": b.cfg.Init.Validators, "blsPublicKeys": pubs},
		},
		"wbftRules": map[string]any{"consensusRules": map[string]any{"rejectNumberJump": at}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHeaderNumberActivation(t *testing.T) {
	b := newBuilder(t)
	h := b.propose(0, nil, nil)
	for _, at := range []any{nil, 0, 1, 2} {
		env := b.env(h.Time)
		env.Config = numberConfig(t, b, at)
		snapshot, err := source.NewAuthoritySnapshot(b.head().Number, h.ParentHash, b.tip, b.set(h, nil).Addresses(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		env.Snapshots = staticSnapshots{h.ParentHash: snapshot}
		if _, err := VerifyProposal(env, &types.Block{Header: h}); err != nil {
			t.Fatalf("activation %v: normal proposal: %v", at, err)
		}
		for _, n := range []uint64{0, 2, 3} {
			bad := h.Copy()
			bad.Number = types.HeightFromUint64(n)
			want := at == 0 || at == 1
			if err := verifyNumber(env, bad, nil); errors.Is(err, ErrInvalidNumber) != want {
				t.Fatalf("activation %v number %d: %v", at, n, err)
			}
			if want {
				if _, err := VerifyProposal(env, &types.Block{Header: bad}); !errors.Is(err, ErrInvalidNumber) {
					t.Fatalf("proposal: %v", err)
				}
				if err := VerifyHeader(env, bad, nil, Options{CheckSeals: true}); !errors.Is(err, ErrInvalidNumber) {
					t.Fatalf("header: %v", err)
				}
			}
		}
	}
}

func TestHeaderNumberBatchParent(t *testing.T) {
	b := newBuilder(t)
	parent := b.propose(0, nil, nil)
	h := parent.Copy()
	h.ParentHash = codec.BlockHash(parent)
	h.Number = types.HeightFromUint64(2)
	env := b.env(h.Time)
	env.Config = numberConfig(t, b, 2)
	if err := verifyNumber(env, h, []*types.Header{parent}); err != nil {
		t.Fatal(err)
	}
	h.Number = types.HeightFromUint64(1)
	if err := VerifyHeader(env, h, []*types.Header{parent}, Options{}); !errors.Is(err, ErrInvalidNumber) {
		t.Fatalf("batch parent was ignored: %v", err)
	}
	wrong := parent.Copy()
	wrong.Time++
	if err := verifyNumber(env, h, []*types.Header{wrong}); !errors.Is(err, ErrUnknownAncestor) {
		t.Fatalf("unrelated batch parent: %v", err)
	}
}
