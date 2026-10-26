package header

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

func randaoConfig(t *testing.T, b *builder, at any) *types.Config {
	t.Helper()
	var keys []string
	for _, pub := range b.cfg.Init.BLSPublicKeys {
		keys = append(keys, "0x"+hex.EncodeToString(pub))
	}
	raw, err := json.Marshal(map[string]any{"chainId": 8282, "anzeon": map[string]any{
		"wbft": map[string]any{"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": 4, "proposerPolicy": 0},
		"init": map[string]any{"validators": b.cfg.Init.Validators, "blsPublicKeys": keys}},
		"wbftRules": map[string]any{"consensusRules": map[string]any{"rejectNumberJump": 0, "blsRandao": at}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBLSRandaoActivationFullLightAndBatch(t *testing.T) {
	for _, at := range []any{nil, 1, 4, 5} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			b := newBuilder(t)
			b.cfg = randaoConfig(t, b, at)
			b.build(7)
			for i := 1; i <= 7; i++ {
				h, parent := b.hs[i], b.hs[i-1]
				x, err := codec.DecodeExtra(h)
				if err != nil {
					t.Fatal(err)
				}
				want := 65
				if at != nil && i >= at.(int) {
					want = bls.SignatureLength
				}
				if len(x.RandaoReveal) != want {
					t.Fatalf("height %d: length %d, want %d", i, len(x.RandaoReveal), want)
				}
				for _, parents := range [][]*types.Header{nil, {parent}} {
					if err := VerifyHeader(b.env(t0+100), h, parents, headerOnly); err != nil {
						t.Fatal("full or batch", i, err)
					}
				}
				if verdict, err := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}}, h, parent); verdict != Valid || err != nil {
					t.Fatal("light", i, verdict, err)
				}
			}
		})
	}
}

// Both inputs are ordinary signatures. Only the selected wire format is valid.
func TestBLSRandaoDoesNotInferFormatFromLength(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		b := newBuilder(t)
		if enabled {
			b.cfg = randaoConfig(t, b, 1)
		}
		h := b.propose(0, nil, nil)
		x, err := codec.DecodeExtra(h)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			x.RandaoReveal, err = ecdsa.SignData(codec.RandaoData(b.cfg.ChainID, h.Number), b.acc[0].key)
		} else {
			x.RandaoReveal = b.acc[0].bls.Sign(codec.BLSRandaoData(b.cfg.ChainID, h.Number)).Bytes()
		}
		if err != nil {
			t.Fatal(err)
		}
		h.MixDigest = RandaoMix(b.head().MixDigest, x.RandaoReveal)
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		h = b.seal(h, 0, []int{0, 1, 2})
		if err := VerifyHeader(b.env(t0+100), h, nil, headerOnly); !errors.Is(err, ErrInvalidRandaoReveal) || stepOf(err) != "H18" {
			t.Fatal("full accepted the other format", enabled, err)
		}
		if verdict, err := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}}, h, b.head()); verdict != Invalid || !errors.Is(err, ErrInvalidRandaoReveal) {
			t.Fatal("light accepted the other format", enabled, verdict, err)
		}
	}
}

type legacyRandaoSigner struct{ key *ecdsa.PrivateKey }

func (s legacyRandaoSigner) SignRandao(data []byte) ([]byte, error) {
	return ecdsa.SignData(data, s.key)
}

func TestBLSRandaoBuilderNeedsSupportedRegisteredKey(t *testing.T) {
	b := newBuilder(t)
	b.cfg = randaoConfig(t, b, 1)
	skeleton := &types.Header{ParentHash: codec.BlockHash(b.head()), Number: types.HeightFromUint64(1)}
	_, err := PrepareProposal(b.env(t0), skeleton, ProposalInputs{Coinbase: b.acc[0].addr, Signer: legacyRandaoSigner{b.acc[0].key}, ParentGasTip: b.tip})
	if !errors.Is(err, ErrMissingBLSRandaoSigner) {
		t.Fatal("legacy-only signer did not refuse activation", err)
	}
	_, err = PrepareProposal(b.env(t0), skeleton, ProposalInputs{Coinbase: b.acc[0].addr, Signer: keySigner{b.acc[1].key}, ParentGasTip: b.tip})
	if err == nil {
		t.Fatal("builder accepted a signature from another registered key")
	}
}

func TestBLSRandaoUsesEpochValidatorKeys(t *testing.T) {
	b := newBuilder(t)
	b.cfg = randaoConfig(t, b, 4)
	b.build(3)
	h4 := b.propose(3, nil, nil)
	ei := &types.EpochInfo{Validators: []uint32{3, 1, 0, 2}}
	for _, i := range []int{0, 1, 2, 4} {
		ei.Candidates = append(ei.Candidates, types.Candidate{Addr: b.acc[i].addr, Diligence: types.DefaultDiligence})
	}
	for _, i := range []int{4, 1, 0, 2} {
		ei.BLSPublicKeys = append(ei.BLSPublicKeys, b.acc[i].bls.PublicKey().Bytes())
	}
	b.setEpochInfo(h4, ei)
	h4 = b.seal(h4, 0, []int{0, 1, 2})
	if err := VerifyHeader(b.env(t0+100), h4, nil, headerOnly); err != nil {
		t.Fatal("epoch header must use prior set", err)
	}
	b.store(h4)
	h5 := b.seal(b.propose(4, nil, nil), 0, []int{0, 1, 2})
	if err := VerifyHeader(b.env(t0+100), h5, nil, headerOnly); err != nil {
		t.Fatal("next header must use new set", err)
	}
	if verdict, err := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}}, h5, h4); verdict != Valid || err != nil {
		t.Fatal(verdict, err)
	}
}

func BenchmarkRandaoVerification(b *testing.B) {
	acc := accounts(b, 1)[0]
	v, err := validator.NewSet([]types.Address{acc.addr}, [][]byte{acc.bls.PublicKey().Bytes()}, types.ProposerPolicy{ID: 0})
	if err != nil {
		b.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			rules := ""
			if enabled {
				rules = `,"wbftRules":{"consensusRules":{"rejectNumberJump":0,"blsRandao":1}}`
			}
			cfg, err := types.ParseChainConfig([]byte(`{"chainId":8282,"anzeon":{"wbft":{"proposerPolicy":0}}` + rules + `}`))
			if err != nil {
				b.Fatal(err)
			}
			parent := &types.Header{}
			h := &types.Header{Number: types.HeightFromUint64(1), Coinbase: acc.addr}
			reveal, err := ecdsa.SignData(codec.RandaoData(big.NewInt(8282), h.Number), acc.key)
			if err != nil {
				b.Fatal(err)
			}
			if enabled {
				reveal = acc.bls.Sign(codec.BLSRandaoData(cfg.ChainID, h.Number)).Bytes()
			}
			b.ResetTimer()
			for b.Loop() {
				if err := verifyRandao(cfg, h, parent, v, reveal); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
