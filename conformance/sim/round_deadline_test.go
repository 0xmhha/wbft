package sim

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/consensus"
)

func TestRoundDeadlinePoliciesNormalSimulation(t *testing.T) {
	for _, flags := range []consensus.ImprovementSet{consensus.ImprovementSet(0).With(consensus.RequireInitialRoundBudget), consensus.ImprovementSet(0).With(consensus.PreserveRoundDeadline), consensus.ImprovementSet(0).With(consensus.RequireInitialRoundBudget).With(consensus.PreserveRoundDeadline), consensus.KnownImprovements()} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", flags, mixed), func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				sc.Params.EpochLength = 2
				for i := range sc.Nodes {
					if !mixed || i%2 == 0 {
						sc.Nodes[i].Options.Improvements |= flags
					}
				}
				r, err := Run(context.Background(), sc, Output{})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Violations) != 0 || r.Refusals != 0 {
					t.Fatal(r.Violations, r.Refusals)
				}
				for _, head := range r.Heads {
					if head < sc.Until.Height {
						t.Fatal("normal network did not progress", r.Heads)
					}
				}
			})
		}
	}
}

func TestInitialBudgetUsesResolvedNodeTimingPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			sc := timingCompatibilityScenario(t, 7)
			sc.Nodes[1].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(1)}
			if enabled {
				sc.Nodes[1].Options.Improvements = sc.Nodes[1].Options.Improvements.With(consensus.RequireInitialRoundBudget)
			}
			_, err := newSimulation(sc)
			if errors.Is(err, ErrScenario) != enabled || err != nil && !errors.Is(err, ErrScenario) {
				t.Fatal("resolved per-node timing budget", err)
			}
		})
	}
}
