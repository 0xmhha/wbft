package header

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func epochProposalBuilder(t *testing.T, at any) (*builder, *types.Header, []types.CandidateEntry, *Env) {
	t.Helper()
	b := newBuilder(t)
	var keys []string
	var candidates []types.CandidateEntry
	for _, a := range b.acc[:4] {
		keys = append(keys, "0x"+hex.EncodeToString(a.bls.PublicKey().Bytes()))
		candidates = append(candidates, types.CandidateEntry{Addr: a.addr, BLSPublicKey: a.bls.PublicKey().Bytes()})
	}
	raw, err := json.Marshal(map[string]any{"chainId": 8282, "anzeon": map[string]any{"wbft": map[string]any{"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": 4, "proposerPolicy": 0}, "init": map[string]any{"validators": b.cfg.Init.Validators, "blsPublicKeys": keys}}, "wbftRules": map[string]any{"consensusRules": map[string]any{"committedEpochDiligence": 0, "epochInfoInProposal": at}}})
	if err != nil {
		t.Fatal(err)
	}
	b.cfg, err = types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	b.build(3)
	h := b.propose(3, nil, nil)
	info, err := epoch.ComputeNextEpochInfo(b.chain, b.cfg, h, candidates)
	if err != nil {
		t.Fatal(err)
	}
	b.setEpochInfo(h, info)
	env := b.env(t0 + 100)
	snapshot, err := source.NewAuthoritySnapshot(b.head().Number, h.ParentHash, b.tip, b.set(h, nil).Addresses(), nil, candidates)
	if err != nil {
		t.Fatal(err)
	}
	env.Snapshots = staticSnapshots{h.ParentHash: snapshot}
	return b, h, candidates, env
}

func TestEpochProposalAtFullHeightBoundary(t *testing.T) {
	for _, at := range []any{nil, 0} {
		b, _, candidates, _ := epochProposalBuilder(t, at)
		base := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(4))
		original := b.hs
		b.hs = nil
		b.chain = newMemChain()
		for i, prior := range original {
			h := prior.Copy()
			h.Number = types.MustHeightFromBig(new(big.Int).Add(base, big.NewInt(int64(i))))
			if i == 0 {
				h.ParentHash = types.Hash{}
			} else {
				h.ParentHash = codec.BlockHash(b.hs[i-1])
			}
			b.store(h)
		}
		h := b.propose(3, nil, nil)
		env := b.env(t0 + 100)
		snapshot, err := source.NewAuthoritySnapshot(b.head().Number, h.ParentHash, b.tip, b.set(h, nil).Addresses(), nil, candidates)
		if err != nil {
			t.Fatal(err)
		}
		env.Snapshots = staticSnapshots{h.ParentHash: snapshot}
		if h.Number.Big().Cmp(new(big.Int).Lsh(big.NewInt(1), 64)) != 0 {
			t.Fatal("wrong test height")
		}
		_, proposalErr := VerifyProposal(env, &types.Block{Header: h})
		headerErr := VerifyHeader(env, h, nil, Options{CheckSeals: false, Mode: HeaderOnly})
		for _, err := range []error{proposalErr, headerErr} {
			if at == nil && err != nil {
				t.Fatal("inactive rule changed legacy classification", err)
			}
			if at != nil && !errors.Is(err, validator.ErrEpochInfoNil) {
				t.Fatal("active rule skipped epoch information", err)
			}
		}
	}
}

func TestEpochProposalChecksAreActivationBound(t *testing.T) {
	for _, at := range []any{nil, 0, 4, 5} {
		b, h, _, env := epochProposalBuilder(t, at)
		active := at == 0 || at == 4
		if _, err := VerifyProposal(env, &types.Block{Header: h}); err != nil {
			t.Fatal(at, err)
		}
		for _, kind := range []string{"missing", "diligence", "key", "validators"} {
			bad := h.Copy()
			x, err := codec.DecodeExtra(bad)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				x.EpochInfo = nil
			case "diligence":
				x.EpochInfo.Candidates[0].Diligence++
			case "key":
				x.EpochInfo.BLSPublicKeys[0][0] ^= 1
			case "validators":
				x.EpochInfo.Validators[0] = (x.EpochInfo.Validators[0] + 1) % 4
			}
			if err := codec.SetExtra(bad, x); err != nil {
				t.Fatal(err)
			}
			_, err = VerifyProposal(env, &types.Block{Header: bad})
			if (err != nil) != active {
				t.Fatalf("activation=%v variant=%s proposal: %v", at, kind, err)
			}
			sealed := b.seal(bad, 0, []int{0, 1, 2})
			err = VerifyHeader(env, sealed, nil, headerOnly)
			if (err != nil) != active {
				t.Fatalf("activation=%v variant=%s header: %v", at, kind, err)
			}
		}
	}
}

func TestEpochProposalCandidateCoverageAndIdentity(t *testing.T) {
	b, h, _, env := epochProposalBuilder(t, 0)
	for _, entry := range []struct {
		name    string
		number  types.Height
		hash    types.Hash
		entries []types.CandidateEntry
		want    error
	}{
		{"missing", b.head().Number, h.ParentHash, nil, ErrSnapshotMissing},
		{"known-empty", b.head().Number, h.ParentHash, []types.CandidateEntry{}, epoch.ErrEpochInfoMismatch},
		{"wrong-hash", b.head().Number, types.Hash{99}, nil, ErrSnapshotMismatch},
		{"wrong-number", types.HeightFromUint64(2), h.ParentHash, nil, ErrSnapshotMismatch},
	} {
		snapshot, err := source.NewAuthoritySnapshot(entry.number, entry.hash, b.tip, b.set(h, nil).Addresses(), nil, entry.entries)
		if err != nil {
			t.Fatal(err)
		}
		env.Snapshots = staticSnapshots{h.ParentHash: snapshot}
		if _, err = VerifyProposal(env, &types.Block{Header: h}); !errors.Is(err, entry.want) {
			t.Fatal(entry.name, err)
		}
		err = VerifyHeader(env, b.seal(h, 0, []int{0, 1, 2}), nil, headerOnly)
		// Only missing state may be deferred by header-only synchronization.
		if entry.want == ErrSnapshotMissing {
			if err != nil {
				t.Fatal(entry.name, err)
			}
		} else if !errors.Is(err, entry.want) {
			t.Fatal(entry.name, err)
		}
	}
}

func TestEpochProposalContextAndBatchAncestry(t *testing.T) {
	b, h, _, env := epochProposalBuilder(t, 4)
	for _, number := range []types.Height{{}, types.HeightFromUint64(3), types.HeightFromUint64(5)} {
		bad := h.Copy()
		bad.Number = number
		if _, err := VerifyProposal(env, &types.Block{Header: bad}); !errors.Is(err, ErrInvalidNumber) {
			t.Fatal(number, err)
		}
	}
	sealed := b.seal(h, 0, []int{0, 1, 2})
	delete(b.chain.byHash, h.ParentHash)
	pending := b.hs[1:]
	if err := VerifyHeader(env, sealed, pending, headerOnly); err != nil {
		t.Fatal("pending parent and scoring ancestry", err)
	}
	wrong := pending[len(pending)-1].Copy()
	wrong.Time++
	if _, err := epochProposalContext(env, h, []*types.Header{wrong}); !errors.Is(err, ErrUnknownAncestor) {
		t.Fatal("unrelated parent", err)
	}
}

func TestEpochProposalPreparedRoundAndLightScope(t *testing.T) {
	b, h, _, env := epochProposalBuilder(t, 0)
	hash := codec.BlockHash(h)
	for _, round := range []uint32{0, 1, 100, 1<<32 - 1} {
		x, err := codec.DecodeExtra(h)
		if err != nil {
			t.Fatal(err)
		}
		x.Round = round
		if err = codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		if codec.BlockHash(h) != hash {
			t.Fatal("round changed proposal digest")
		}
		if _, err := VerifyProposal(env, &types.Block{Header: h}); err != nil {
			t.Fatal(round, err)
		}
	}
	sealed := b.seal(h, 0, []int{0, 1, 2})
	if verdict, err := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}}, sealed, b.head()); verdict != CannotDecide || !errors.Is(err, ErrLightMissing) {
		t.Fatal("header-only light input claims candidate validation", verdict, err)
	}
	bad := h.Copy()
	b.setEpochInfo(bad, nil)
	if _, err := VerifyProposal(env, &types.Block{Header: bad}); !errors.Is(err, validator.ErrEpochInfoNil) {
		t.Fatal(err)
	}
}
