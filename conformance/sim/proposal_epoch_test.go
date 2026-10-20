package sim

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestProposalEpochUsesCommittedParentCandidates(t *testing.T) {
	for _, at := range []string{"", "0", "4", "5"} {
		t.Run("activation_"+at, func(t *testing.T) {
			sc := timingCompatibilityScenario(t, 2)
			sc.Schedule = nil
			sc.Epochs = []EpochChange{{Block: 4, Candidates: []int{0, 1, 2}}}
			if at != "" {
				sc.Params.RuleActivations = map[types.RuleName]string{types.EpochInfoInProposal: at, types.CommittedEpochDiligence: "0"}
			}
			result, err := Run(context.Background(), sc, Output{})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Violations) != 0 {
				t.Fatal(result.Violations)
			}
			for _, head := range result.Heads {
				if head < sc.Until.Height {
					t.Fatal("normal epoch transition did not complete", result.Heads)
				}
			}
			for _, n := range []uint64{4, 8} {
				extra, err := codec.DecodeExtra(result.Chain[n].Header)
				if err != nil || extra.EpochInfo == nil {
					t.Fatal("missing epoch", n, err)
				}
				want := 3
				if n == 4 && (at == "0" || at == "4") {
					want = 4
				}
				if len(extra.EpochInfo.Candidates) != want {
					t.Fatal("wrong candidate state", at, n, len(extra.EpochInfo.Candidates), want)
				}
			}
			expectedPartial := 0
			switch at {
			case "0", "4":
				expectedPartial = 2
			case "5":
				expectedPartial = 1
			}
			partialHeights := map[string]bool{}
			for _, check := range result.LightChecks {
				if check.Verdict != "CANNOT_DECIDE" || !check.FullStateVerified || check.Reason != "light: missing input: parent candidate state and epoch ancestry" {
					t.Fatal(check)
				}
				var number uint64
				switch check.Number {
				case "4":
					number = 4
				case "8":
					number = 8
				default:
					t.Fatal("unexpected partial check height", check)
				}
				if check.Hash != codec.BlockHash(result.Chain[number].Header) {
					t.Fatal("partial check does not identify the committed block", check)
				}
				partialHeights[check.Number] = true
			}
			if len(partialHeights) != expectedPartial {
				t.Fatal("partial light check heights not retained", at, result.LightChecks)
			}
			raw, err := chainConfigJSON(sc.Params, sc.Validators)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Rules struct {
					Source map[string]json.RawMessage `json:"sourceRules"`
				} `json:"wbftRules"`
			}
			if err = json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			if at != "" && string(config.Rules.Source["candidatesFromParentState"]) != at {
				t.Fatal("parent source declaration absent", string(raw))
			}
		})
	}
}
