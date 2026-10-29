package header

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// This fixture contains no signatures, packets, transactions or executed state.
// It measures presence-check ordering, never acceptance of a signed block.
func epochPresenceMetadata(t *testing.T, number uint64, info *types.EpochInfo) (*Env, *types.Header) {
	t.Helper()
	policy := uint64(0)
	address := types.Address{19: 1}
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 4, BlockPeriodSeconds: 1, ProposerPolicy: &policy}, nil, types.GenesisInit{}, big.NewInt(7))
	members, err := validator.NewSet([]types.Address{address}, [][]byte{nil}, types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	parent := &types.Header{Number: types.HeightFromUint64(number - 1), Time: 100, Difficulty: big.NewInt(1)}
	if err := codec.SetExtra(parent, &types.WBFTExtra{GasTip: big.NewInt(0)}); err != nil {
		t.Fatal(err)
	}
	chain := newMemChain()
	chain.add(parent)
	h := &types.Header{Number: types.HeightFromUint64(number), ParentHash: codec.BlockHash(parent), Time: 101, Difficulty: big.NewInt(1), Coinbase: address}
	if err := codec.SetExtra(h, &types.WBFTExtra{GasTip: big.NewInt(0), EpochInfo: info}); err != nil {
		t.Fatal(err)
	}
	env := &Env{Config: cfg, Chain: chain, Now: func() time.Time { return time.Unix(1000, 0) }, ValidatorLookup: func(types.Height, types.Hash, []*types.Header) (*validator.Set, error) { return members, nil }}
	return env, h
}

func TestEpochPresenceBaselineUnsignedMetadata(t *testing.T) {
	cases := []struct {
		name   string
		number uint64
		info   *types.EpochInfo
	}{
		{"non_epoch_extra", 1, &types.EpochInfo{}},
		{"epoch_missing", 4, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, h := epochPresenceMetadata(t, tc.number, tc.info)
			before, err := codec.EncodeHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			x, err := codec.DecodeExtra(h)
			if err != nil {
				t.Fatal(err)
			}
			for _, seal := range []*types.AggregatedSeal{x.PreparedSeal, x.CommittedSeal, x.PrevPreparedSeal, x.PrevCommittedSeal} {
				if seal != nil && len(seal.Signature) != 0 {
					t.Fatal("fixture contains a signature")
				}
			}
			if len(x.RandaoReveal) != 0 {
				t.Fatal("fixture contains a randao signature")
			}
			err = VerifyHeader(env, h, nil, Options{CheckSeals: true, Mode: HeaderOnly})
			var step *StepError
			if !errors.As(err, &step) || step.Step != "H17" || errors.Is(err, validator.ErrEpochInfoNil) || errors.Is(err, epoch.ErrEpochInfoIsNotNil) {
				t.Fatal("baseline did not reach the later seal check", err)
			}
			after, encodeErr := codec.EncodeHeader(h)
			if encodeErr != nil || !bytes.Equal(before, after) {
				t.Fatal("metadata changed", encodeErr)
			}
			fmt.Printf("baseline_unsigned=%s step=%s signed_headers=0 packets=0 state_execution=0\n", tc.name, step.Step)
		})
	}
}

type epochPresenceTrusted struct{ set *validator.Set }

func (t epochPresenceTrusted) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	return t.set, nil
}

func TestEpochPresenceUnsignedOrderingPair(t *testing.T) {
	for _, n := range []uint64{1, 4} {
		for _, present := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				for _, seals := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/%t/%t/%t", n, present, enabled, seals), func(t *testing.T) {
						var info *types.EpochInfo
						if present {
							info = &types.EpochInfo{}
						}
						env, h := epochPresenceMetadata(t, n, info)
						env.CheckEpochInfoPresence = enabled
						before, _ := codec.EncodeHeader(h)
						err := VerifyHeader(env, h, nil, Options{CheckSeals: seals, Mode: HeaderOnly})
						wantPresence := enabled && present != (n == 4)
						if wantPresence {
							want := epoch.ErrEpochInfoIsNotNil
							if n == 4 {
								want = validator.ErrEpochInfoNil
							}
							var step *StepError
							if !errors.Is(err, want) || !errors.As(err, &step) || step.Step != "epoch_info_presence" {
								t.Fatal("selected presence did not run before signatures", err)
							}
						} else {
							var step *StepError
							want := "H18"
							if seals {
								want = "H17"
							}
							if !errors.As(err, &step) || step.Step != want {
								t.Fatal("legacy signature order changed", err, want)
							}
						}
						parent := env.Chain.HeaderByHash(h.ParentHash)
						set, _ := env.ValidatorLookup(h.Number, h.ParentHash, nil)
						result, lightErr := VerifyLight(LightInputs{Config: env.Config, Trusted: epochPresenceTrusted{set}, CheckEpochInfoPresence: enabled}, h, parent)
						var lightStep *StepError
						if result != Invalid || !errors.As(lightErr, &lightStep) {
							t.Fatal("unsigned light result", result, lightErr)
						}
						wantStep := "H17"
						if wantPresence {
							wantStep = "epoch_info_presence"
						}
						if lightStep.Step != wantStep {
							t.Fatal("light presence order", lightErr, wantStep)
						}
						snap, e := source.NewAuthoritySnapshot(parent.Number, h.ParentHash, uint256.NewInt(0), set.Addresses(), nil, nil)
						if e != nil {
							t.Fatal(e)
						}
						env.Snapshots = staticSnapshots{h.ParentHash: snap}
						_, proposalErr := VerifyProposal(env, &types.Block{Header: h})
						var proposalStep *StepError
						wantProposal := "H18"
						if wantPresence {
							wantProposal = "epoch_info_presence"
						}
						if !errors.As(proposalErr, &proposalStep) || proposalStep.Step != wantProposal {
							t.Fatal("unsigned proposal metadata order", proposalErr, wantProposal)
						}
						after, _ := codec.EncodeHeader(h)
						if !bytes.Equal(before, after) {
							t.Fatal("readonly checks changed metadata")
						}
					})
				}
			}
		}
	}
}

func TestEpochPresencePureScheduleMetadata(t *testing.T) {
	policy := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 4, ProposerPolicy: &policy}, []types.Transition{{Block: big.NewInt(6), WBFT: &types.WBFTParams{EpochLength: 3}}}, types.GenesisInit{}, big.NewInt(7))
	for _, tc := range []struct {
		number uint64
		epoch  bool
	}{{0, true}, {1, false}, {3, false}, {4, true}, {5, false}, {6, true}, {7, false}, {8, false}, {9, true}} {
		for _, present := range []bool{false, true} {
			h := &types.Header{Number: types.HeightFromUint64(tc.number)}
			x := &types.WBFTExtra{}
			if present {
				x.EpochInfo = &types.EpochInfo{}
			}
			before, _ := json.Marshal([]any{h, x, cfg.Base(), cfg.EpochTransitions()})
			err := checkEpochInfoPresence(cfg, h, x)
			if (err == nil) != (present == tc.epoch) {
				t.Fatal("transition presence", tc, present, err)
			}
			after, _ := json.Marshal([]any{h, x, cfg.Base(), cfg.EpochTransitions()})
			if !bytes.Equal(before, after) {
				t.Fatal("pure check changed its inputs")
			}
		}
	}
	full := types.NewConfig(types.WBFTParams{EpochLength: 3, ProposerPolicy: &policy}, nil, types.GenesisInit{}, big.NewInt(7))
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for _, tc := range []struct {
		number *big.Int
		epoch  bool
	}{{two64, false}, {new(big.Int).Add(new(big.Int).Set(two64), big.NewInt(2)), true}, {new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), true}} {
		h := &types.Header{Number: types.MustHeightFromBig(tc.number)}
		x := &types.WBFTExtra{EpochInfo: &types.EpochInfo{}}
		err := checkEpochInfoPresence(full, h, x)
		if (err == nil) != tc.epoch {
			t.Fatal("full-height schedule truncated", tc.number, err)
		}
	}
	h := &types.Header{}
	x := &types.WBFTExtra{EpochInfo: &types.EpochInfo{}}
	for _, tc := range []struct {
		cfg  *types.Config
		h    *types.Header
		x    *types.WBFTExtra
		want error
	}{{nil, h, x, ErrMissingConfig}, {cfg, nil, x, ErrInvalidProposal}, {cfg, h, nil, ErrInvalidExtraDataFormat}, {types.NewConfig(types.WBFTParams{}, nil, types.GenesisInit{}, nil), h, x, validator.ErrZeroEpochLength}} {
		if err := checkEpochInfoPresence(tc.cfg, tc.h, tc.x); !errors.Is(err, tc.want) {
			t.Fatal("missing input was not rejected", err, tc.want)
		}
	}
	// Exercise the public light result as well as the pure helper's cause.
	env, metadata := epochPresenceMetadata(t, 1, nil)
	members, _ := env.ValidatorLookup(metadata.Number, metadata.ParentHash, nil)
	zero := types.NewConfig(types.WBFTParams{BlockPeriodSeconds: 1}, nil, types.GenesisInit{}, big.NewInt(7))
	verdict, err := VerifyLight(LightInputs{Config: zero, Trusted: epochPresenceTrusted{members}, CheckEpochInfoPresence: true}, metadata, env.Chain.HeaderByHash(metadata.ParentHash))
	if verdict != CannotDecide || !errors.Is(err, validator.ErrZeroEpochLength) {
		t.Fatal("undefined schedule was classified as a definite header verdict", verdict, err)
	}
	verdict, err = VerifyLight(LightInputs{Trusted: epochPresenceTrusted{members}, CheckEpochInfoPresence: true}, metadata, nil)
	if verdict != CannotDecide || !errors.Is(err, ErrMissingConfig) {
		t.Fatal("missing light config did not stay undecidable", verdict, err)
	}
}

func TestEpochPresenceH10MetadataFastPaths(t *testing.T) {
	for _, minimal := range []bool{false, true} {
		env, h := epochPresenceMetadata(t, 1, nil)
		if minimal {
			cfg, err := types.ParseChainConfig([]byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":3,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"minimalSealerBitmap":100}}}`))
			if err != nil {
				t.Fatal(err)
			}
			env.Config = cfg
		} else {
			p := uint64(0)
			env.Config = types.NewConfig(types.WBFTParams{EpochLength: 3, ProposerPolicy: &p}, nil, types.GenesisInit{}, big.NewInt(7))
		}
		h.Number = types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 64))
		if err := codec.SetExtra(h, &types.WBFTExtra{GasTip: big.NewInt(0), EpochInfo: &types.EpochInfo{}}); err != nil {
			t.Fatal(err)
		}
		env.CheckEpochInfoPresence = true
		if err := VerifyHeader(env, h, nil, Options{CheckSeals: true}); !errors.Is(err, epoch.ErrEpochInfoIsNotNil) {
			t.Fatal("low64 fast path skipped full-height presence", minimal, err)
		}
		h.Number = types.Height{}
		h.ParentHash = types.Hash{}
		if err := codec.SetExtra(h, &types.WBFTExtra{GasTip: big.NewInt(0)}); err != nil {
			t.Fatal(err)
		}
		if err := VerifyHeader(env, h, nil, Options{}); !errors.Is(err, validator.ErrEpochInfoNil) {
			t.Fatal("genesis presence missing", minimal, err)
		}
		if err := codec.SetExtra(h, &types.WBFTExtra{GasTip: big.NewInt(0), EpochInfo: &types.EpochInfo{}}); err != nil {
			t.Fatal(err)
		}
		if err := VerifyHeader(env, h, nil, Options{}); err != nil {
			t.Fatal("presence-only genesis check inferred candidate validity", err)
		}
		h.Extra = []byte{1}
		if err := VerifyHeader(env, h, nil, Options{}); !errors.Is(err, ErrInvalidExtraDataFormat) {
			t.Fatal("inactive bitmap fast path bypassed selected format", minimal, err)
		}
	}
}

func TestEpochPresenceHeaderBatchUnsignedMetadata(t *testing.T) {
	env, h := epochPresenceMetadata(t, 1, &types.EpochInfo{})
	env.CheckEpochInfoPresence = true
	results := VerifyHeaderBatch(env, []*types.Header{h, h}, Options{CheckSeals: false})
	if len(results) != 2 || !errors.Is(results[0], epoch.ErrEpochInfoIsNotNil) || !errors.Is(results[1], ErrUnknownAncestor) {
		t.Fatal("batch classification", results)
	}
	index := 0
	for err := range VerifyHeaders(context.Background(), env, []*types.Header{h, h}, Options{CheckSeals: false}) {
		if index == 0 && !errors.Is(err, epoch.ErrEpochInfoIsNotNil) || index == 1 && !errors.Is(err, ErrUnknownAncestor) {
			t.Fatal("ordered delivery", index, err)
		}
		index++
	}
	if index != 2 {
		t.Fatal("missing batch result", index)
	}
}

// Every signature in these positive cases is produced by the normal builder.
func TestEpochPresenceNormalHeadersAndLight(t *testing.T) {
	b := newBuilder(t)
	b.build(7)
	// The existing fixture has seven scheduled entries. Build the eighth
	// normally, adding epoch metadata before producing its ordinary seals.
	next := b.propose(2, nil, nil)
	previousEpoch, err := codec.DecodeExtra(b.hs[4])
	if err != nil {
		t.Fatal(err)
	}
	b.setEpochInfo(next, previousEpoch.EpochInfo)
	b.store(b.seal(next, 0, []int{0, 1, 2}))
	if len(b.hs) != 9 {
		t.Fatal("normal eight-header fixture is incomplete")
	}
	for _, enabled := range []bool{false, true} {
		for index, h := range b.hs[1:] {
			env := b.env(t0 + 100)
			env.CheckEpochInfoPresence = enabled
			if err := VerifyHeader(env, h, nil, headerOnly); err != nil {
				t.Fatal("normal header", enabled, h.Number, err)
			}
			verdict, err := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}, CheckEpochInfoPresence: enabled}, h, b.hs[index])
			if verdict != Valid || err != nil {
				t.Fatal("normal light", enabled, h.Number, verdict, err)
			}
		}
	}
}
