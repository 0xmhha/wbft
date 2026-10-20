package consensus

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

// Fixed ordinary settings compare local timing policy with the unchanged
// reference function. No network payload or fault input is constructed.
func TestInitialRoundCapOrdinaryPair(t *testing.T) {
	cases := []struct {
		name             string
		base, cap, round uint64
		off, on          time.Duration
		offWarn          TimeoutWarning
	}{
		{"long-first", 1000000, 4, 0, 1000 * time.Second, 4 * time.Second, NoWarning},
		{"long-later", 1000000, 4, 1, 4 * time.Second, 4 * time.Second, CapOverflowGuard},
		{"normal-first", 2000, 4, 0, 2 * time.Second, 2 * time.Second, NoWarning},
		{"normal-later", 2000, 4, 1, 4 * time.Second, 4 * time.Second, NoWarning},
		{"equal-first", 4000, 4, 0, 4 * time.Second, 4 * time.Second, NoWarning},
		{"uncapped-first", 1000000, 0, 0, 1000 * time.Second, 1000 * time.Second, NoWarning},
		{"uncapped-later", 2000, 0, 2, 8 * time.Second, 8 * time.Second, NoWarning},
		{"ordinary-capped", 2000, 10, 3, 10 * time.Second, 10 * time.Second, NoWarning},
	}
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(CapInitialRoundTimeout)} {
		for _, row := range cases {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/%t", base, row.name, enabled), func(t *testing.T) {
					flags := base
					want, warn := row.off, row.offWarn
					if enabled {
						flags = flags.With(CapInitialRoundTimeout)
						want, warn = row.on, NoWarning
					}
					params := types.Params{RequestTimeoutMs: row.base, MaxRequestTimeoutSeconds: row.cap}
					round := types.RoundFromUint64(row.round)
					got, warning := roundTimeoutWithOptions(params, round, flags)
					if got != want || warning != warn {
						t.Fatal(got, warning, want, warn)
					}
					ref, refWarn := RoundTimeout(params, round)
					if ref != row.off || refWarn != row.offWarn {
						t.Fatal("public reference computation changed", ref, refWarn)
					}
				})
			}
		}
	}
}

func TestInitialRoundCapConfigAtPair(t *testing.T) {
	for _, baseFlags := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(CapInitialRoundTimeout)} {
		for _, at := range []int64{10, 11} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%d/%t", baseFlags, at, enabled), func(t *testing.T) {
					policy, cap := uint64(0), uint64(4)
					h := newHarness(t, 4, 1)
					base := types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: &cap}
					h.cfg = types.NewConfig(base, []types.Transition{{Block: big.NewInt(at), WBFT: &types.WBFTParams{RequestTimeoutSeconds: 1000}}}, types.GenesisInit{}, nil)
					flags := baseFlags
					if enabled {
						flags = flags.With(CapInitialRoundTimeout)
					}
					withImprovements(h, flags)
					var arms []ArmTimer
					for _, arm := range outputsOf[ArmTimer](h.start()) {
						if arm.Kind == RoundTimer {
							arms = append(arms, arm)
						}
					}
					want := 2 * time.Second
					if at == 10 {
						want = 1000 * time.Second
						if enabled {
							want = 4 * time.Second
						}
					}
					if len(arms) != 1 || arms[0].Duration != want || arms[0].View.Cmp(view(10, 0)) != 0 {
						t.Fatal("current-height timing configuration lost", arms, want)
					}
				})
			}
		}
	}
}
