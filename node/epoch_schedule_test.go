package node

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/types"
)

func epochScheduleConfig(base uint64, transitions []types.Transition) *types.Config {
	policy := uint64(0)
	return types.NewConfig(types.WBFTParams{EpochLength: base, ProposerPolicy: &policy}, transitions,
		types.GenesisInit{Validators: []types.Address{{1}}, BLSPublicKeys: [][]byte{{1}}}, nil)
}

func epochScheduleTransition(block string, length uint64) types.Transition {
	n, ok := new(big.Int).SetString(block, 10)
	if !ok {
		panic("invalid test height")
	}
	return types.Transition{Block: n, WBFT: &types.WBFTParams{EpochLength: length, RequestTimeoutSeconds: 3}}
}

func TestEpochScheduleStartupChecks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		base    uint64
		changes []types.Transition
		refuse  bool
	}{
		{"ordinary", 4, nil, false},
		{"minimum", 2, nil, false},
		{"zero-base", 0, nil, true},
		{"one-base", 1, nil, true},
		{"one-transition", 4, []types.Transition{epochScheduleTransition("6", 1)}, true},
		{"adjacent", 4, []types.Transition{epochScheduleTransition("5", 4)}, true},
		{"first-block", 4, []types.Transition{epochScheduleTransition("1", 4)}, true},
		{"two-block-interval", 4, []types.Transition{epochScheduleTransition("6", 2)}, false},
		{"on-old-boundary", 4, []types.Transition{epochScheduleTransition("8", 3)}, false},
		{"zero-keeps-schedule", 4, []types.Transition{epochScheduleTransition("5", 0)}, false},
		{"zero-does-not-reanchor", 4, []types.Transition{epochScheduleTransition("5", 0), epochScheduleTransition("6", 4)}, false},
		{"new-anchor-adjacent", 4, []types.Transition{epochScheduleTransition("6", 3), epochScheduleTransition("7", 4)}, true},
		{"new-anchor-minimum", 4, []types.Transition{epochScheduleTransition("6", 3), epochScheduleTransition("8", 4)}, false},
		{"same-block", 4, []types.Transition{epochScheduleTransition("6", 2), epochScheduleTransition("6", 4)}, false},
		{"same-block-invalid-length", 4, []types.Transition{epochScheduleTransition("6", 1), epochScheduleTransition("6", 4)}, true},
		{"zero-anchor", 4, []types.Transition{epochScheduleTransition("0", 2)}, false},
		{"full-height-adjacent", 4, []types.Transition{epochScheduleTransition("18446744073709551617", 4)}, true},
		{"full-height-valid", 4, []types.Transition{epochScheduleTransition("18446744073709551618", 4)}, false},
		{"full-height-new-anchor", 4, []types.Transition{epochScheduleTransition("18446744073709551618", 4), epochScheduleTransition("18446744073709551619", 2)}, true},
		{"negative-anchor-first-boundary", 4, []types.Transition{epochScheduleTransition("-3", 4)}, true},
		{"negative-anchor-control", 4, []types.Transition{epochScheduleTransition("-2", 4)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := epochScheduleConfig(tc.base, tc.changes)
			before := cfg.Transitions()
			err := checkChainConfig(cfg)
			if (err != nil) != tc.refuse {
				t.Fatalf("startup check=%v, refusal expected=%v", err, tc.refuse)
			}
			if err != nil && !errors.Is(err, ErrStartRefused) {
				t.Fatalf("wrong error class: %v", err)
			}
			if !reflect.DeepEqual(before, cfg.Transitions()) {
				t.Fatal("startup validation changed transition order or fields")
			}
		})
	}
}

// Enumerating actual epoch boundaries independently checks reanchoring,
// equal-height transition order, and schedules with no length override.
func TestEpochScheduleCheckMatchesBoundaries(t *testing.T) {
	for base := uint64(2); base <= 5; base++ {
		for first := int64(-3); first <= 9; first++ {
			for second := first; second <= 10; second++ {
				for a := uint64(0); a <= 5; a++ {
					if a == 1 {
						continue
					}
					for b := uint64(0); b <= 5; b++ {
						if b == 1 {
							continue
						}
						cfg := epochScheduleConfig(base, []types.Transition{
							{Block: big.NewInt(first), WBFT: &types.WBFTParams{EpochLength: a, RequestTimeoutSeconds: 3}},
							{Block: big.NewInt(second), WBFT: &types.WBFTParams{EpochLength: b, RequestTimeoutSeconds: 3}},
						})
						bad := false
						previous := uint64(0)
						for height := uint64(1); height <= 20; height++ {
							isEpoch, err := validator.IsEpochBlock(cfg, types.HeightFromUint64(height))
							if err != nil {
								t.Fatal(err)
							}
							if isEpoch {
								if height-previous == 1 {
									bad = true
								}
								previous = height
							}
						}
						if err := checkChainConfig(cfg); (err != nil) != bad {
							t.Fatalf("base=%d transitions=(%d,%d),(%d,%d): err=%v consecutive=%v", base, first, a, second, b, err, bad)
						}
					}
				}
			}
		}
	}
}
