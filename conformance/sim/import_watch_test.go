package sim

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
)

func TestImportWatchdogNormalSimulation(t *testing.T) {
	for _, configuration := range []string{"legacy", "all", "mixed"} {
		for _, delayed := range []bool{false, true} {
			t.Run(configuration+map[bool]string{false: "_normal", true: "_bounded_import_delay"}[delayed], func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				sc.Schedule = nil
				sc.Until.Duration = 2 * time.Minute
				if delayed {
					sc.App.ImportDelay = []time.Duration{time.Second}
				}
				for i := range sc.Nodes {
					if configuration == "all" || configuration == "mixed" && i%2 == 0 {
						sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.WatchCommittedImport).With(consensus.AdvanceOnCommitFailure)
					}
				}
				result, err := Run(context.Background(), sc, Output{})
				if err != nil || len(result.Violations) != 0 {
					t.Fatal(err, result.Violations)
				}
				for _, head := range result.Heads {
					if head < sc.Until.Height {
						t.Fatal("ordinary delayed import did not progress", result.Heads)
					}
				}
			})
		}
	}
}

// This larger delay pins a known progress boundary separately from the
// normal progress cases. Partial deployment does not close that boundary.
func TestImportWatchdogSlowImportBoundary(t *testing.T) {
	for _, configuration := range []string{"legacy", "all", "mixed"} {
		t.Run(configuration, func(t *testing.T) {
			sc := timingCompatibilityScenario(t, 7)
			sc.Schedule = nil
			sc.App.ImportDelay = []time.Duration{3 * time.Second}
			sc.Until.Duration = 2 * time.Minute
			for i := range sc.Nodes {
				if configuration == "all" || configuration == "mixed" && i%2 == 0 {
					sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.WatchCommittedImport).With(consensus.AdvanceOnCommitFailure)
				}
			}
			result, err := Run(context.Background(), sc, Output{})
			if err != nil {
				t.Fatal(err)
			}
			if configuration == "all" {
				if len(result.Violations) != 0 {
					t.Fatal(result.Violations)
				}
				for _, head := range result.Heads {
					if head < sc.Until.Height {
						t.Fatal("enabled monitor did not progress", result.Heads)
					}
				}
				return
			}
			if len(result.Violations) != len(sc.Nodes) {
				t.Fatal("known boundary changed", result.Violations)
			}
			for _, violation := range result.Violations {
				if violation.Kind != "progress" {
					t.Fatal("unexpected non-progress violation", violation)
				}
			}
			for _, head := range result.Heads {
				if head != 1 {
					t.Fatal("known baseline progress changed", result.Heads)
				}
			}
			t.Logf("known progress boundary retained: configuration=%s heads=%v; not a liveness acceptance", configuration, result.Heads)
		})
	}
}
