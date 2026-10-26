package sim

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
)

func TestProposalAuthorNormalSimulationPair(t *testing.T) {
	var baseline [][]byte
	for _, enabled := range []bool{false, true} {
		sc := timingCompatibilityScenario(t, 7)
		sc.Params.EpochLength = 2
		for i := range sc.Nodes {
			if enabled {
				sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.BindFreshProposalAuthor)
			}
		}
		result, err := Run(context.Background(), sc, Output{})
		if err != nil || len(result.Violations) != 0 || result.Refusals != 0 {
			t.Fatal("normal network", enabled, err, result.Violations, result.Refusals)
		}
		for _, head := range result.Heads {
			if head < sc.Until.Height {
				t.Fatal("normal network did not progress", enabled, result.Heads)
			}
		}
		if enabled && len(result.Chain) != len(baseline) {
			t.Fatal("normal chain length changed")
		}
		for i, block := range result.Chain {
			raw, err := codec.EncodeHeader(block.Header)
			if err != nil {
				t.Fatal(err)
			}
			if !enabled {
				baseline = append(baseline, raw)
			} else if !bytes.Equal(raw, baseline[i]) {
				t.Fatal("normal signed header changed", i)
			}
		}
	}
}
