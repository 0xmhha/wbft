package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/types"
)

// These are ordinary local configurations, including effective future and
// equal-height transitions. No network or fault input is constructed.
func TestInitialRoundBudgetConfigurationPair(t *testing.T) {
	policy, cap := uint64(0), uint64(1)
	wide := new(big.Int).Lsh(big.NewInt(1), 64)
	for _, row := range []struct {
		name            string
		request, period uint64
		transitions     []types.Transition
		cap             *uint64
		insufficient    bool
	}{
		{"base-less", 1, 2, nil, nil, true},
		{"base-equal", 1, 1, nil, nil, true},
		{"base-greater", 2, 1, nil, nil, false},
		{"future-equal", 2, 1, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 1}}}, nil, true},
		{"future-greater", 2, 1, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 3}}}, nil, false},
		{"wide-equal", 2, 1, []types.Transition{{Block: wide, WBFT: &types.WBFTParams{BlockPeriodSeconds: 2}}}, nil, true},
		{"inherit-zero", 2, 1, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{}}}, nil, false},
		{"equal-height-final-valid", 2, 1, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 1}}, {Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 3}}}, nil, false},
		{"equal-height-final-equal", 2, 1, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 3}}, {Block: big.NewInt(10), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 1}}}, nil, true},
		{"zero-height-final-valid", 1, 1, []types.Transition{{Block: big.NewInt(0), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 3}}}, nil, false},
		{"cap-selected", 10, 1, nil, &cap, true},
	} {
		for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(RequireInitialRoundBudget)} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/%t", row.name, base, enabled), func(t *testing.T) {
					flags := base
					if row.cap != nil {
						flags = flags.With(CapInitialRoundTimeout)
					}
					if enabled {
						flags = flags.With(RequireInitialRoundBudget)
					}
					cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: row.request, BlockPeriodSeconds: row.period, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: row.cap}, row.transitions, types.GenesisInit{}, nil)
					err := CheckInitialRoundBudget(cfg, flags)
					if errors.Is(err, ErrInitialRoundBudget) != (enabled && row.insufficient) || err != nil && !errors.Is(err, ErrInitialRoundBudget) {
						t.Fatal("selected configuration budget", err)
					}
				})
			}
		}
	}
}

func TestInitialRoundBudgetUsesSelectedCap(t *testing.T) {
	policy, cap := uint64(0), uint64(1)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 10, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: &cap}, nil, types.GenesisInit{}, nil)
	for _, capped := range []bool{false, true} {
		for _, checked := range []bool{false, true} {
			t.Run(fmt.Sprintf("cap=%t/check=%t", capped, checked), func(t *testing.T) {
				flags := RestartSafety
				if capped {
					flags = flags.With(CapInitialRoundTimeout)
				}
				if checked {
					flags = flags.With(RequireInitialRoundBudget)
				}
				if err := CheckInitialRoundBudget(cfg, flags); errors.Is(err, ErrInitialRoundBudget) != (capped && checked) {
					t.Fatal("budget did not follow selected initial cap", err)
				}
			})
		}
	}
}
