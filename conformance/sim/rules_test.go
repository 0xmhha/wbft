package sim

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestChainRuleActivationIsSnapshottedAndIndependentOfNodeTiming(t *testing.T) {
	sc := timingCompatibilityScenario(t, 2)
	sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "4"}
	sc.Params.AllowedFutureBlockTime = timingValue(3)
	sc.Nodes[1].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(3)}
	resolved, err := ResolveTiming(sc.Params, sc.Nodes[1].Timing, sc.Until.Duration)
	if err != nil {
		t.Fatal(err)
	}
	resolved.RuleActivations[types.RejectNumberJump] = "99"
	*resolved.AllowedFutureBlockTime = 99
	if sc.Params.RuleActivations[types.RejectNumberJump] != "4" {
		t.Fatal("resolved timing aliases caller chain rules")
	}
	if *sc.Params.AllowedFutureBlockTime != 3 {
		t.Fatal("resolved timing aliases future-block allowance")
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.Params.RuleActivations[types.RejectNumberJump] = "100"
	*sc.Params.AllowedFutureBlockTime = 100
	if s.sc.Params.RuleActivations[types.RejectNumberJump] != "4" {
		t.Fatal("simulation rule declaration aliases caller")
	}
	for i, node := range s.nodes {
		at, enabled := node.cfg.RuleActivation(types.RejectNumberJump)
		if !enabled || at.String() != "4" || node.cfg.Rules(types.RejectNumberJump, types.HeightFromUint64(3)) || !node.cfg.Rules(types.RejectNumberJump, types.HeightFromUint64(4)) {
			t.Fatal("node timing or profile changed chain activation", i, at, enabled)
		}
		if node.cfg.ConfigAt(types.HeightFromUint64(4)).AllowedFutureBlockTime != 3 || *s.sc.Params.AllowedFutureBlockTime != 3 {
			t.Fatal("future-block allowance changed after startup", i)
		}
	}
	if s.nodes[0].cfg.RulesDigest() == s.nodes[1].cfg.RulesDigest() {
		t.Fatal("per-node timing configuration was not retained in digest")
	}
}

func TestChainRuleActivationSurvivesActualJournalAndRestart(t *testing.T) {
	sc := timingCompatibilityScenario(t, 7)
	sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "4", types.MinimalSealerBitmap: "4", types.StableCandidateSort: "4"}
	sc.Params.AllowedFutureBlockTime = timingValue(3)
	sc.Nodes[1].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(3)}
	dir := t.TempDir()
	result, err := Run(context.Background(), sc, Output{JournalDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 {
		t.Fatal(result.Violations)
	}
	for _, head := range result.Heads {
		if head < sc.Until.Height {
			t.Fatal("configured nodes did not reach the stop height", result.Heads)
		}
	}
	for i, v := range sc.Validators {
		key, err := NewValidator(v.ECDSA)
		if err != nil {
			t.Fatal(err)
		}
		records, err := journal.ReadAll(nil, filepath.Join(dir, strings.TrimPrefix(strings.ToLower(key.Address().Hex()), "0x")))
		if err != nil {
			t.Fatal(err)
		}
		runs := map[string]bool{}
		for _, record := range records {
			segment, ok := record.Body.(*journal.SegmentRec)
			if !ok {
				continue
			}
			runs[segment.Run] = true
			cfg, err := types.ParseChainConfig(segment.Core.ChainConfig)
			if err != nil {
				t.Fatal(err)
			}

			for _, rule := range []types.RuleName{types.RejectNumberJump, types.MinimalSealerBitmap, types.StableCandidateSort} {
				at, enabled := cfg.RuleActivation(rule)
				if !enabled || at.String() != "4" || cfg.Rules(rule, types.HeightFromUint64(3)) || !cfg.Rules(rule, types.HeightFromUint64(4)) || cfg.RulesDigest() == (types.Hash{}) {
					t.Fatal("actual journal lost chain rule or digest", i, rule, at, enabled)
				}
			}
			want := uint64(2000)
			if i == 1 {
				want = 3000
			}
			if cfg.ConfigAt(types.HeightFromUint64(4)).RequestTimeoutMs != want {
				t.Fatal("rule declaration replaced node timing", i)
			}
			if cfg.ConfigAt(types.HeightFromUint64(4)).AllowedFutureBlockTime != 3 {
				t.Fatal("actual journal lost future-block allowance", i)
			}
		}
		if len(runs) == 0 || i == 3 && len(runs) != 2 {
			t.Fatal("actual startup or restarted configuration not observed", i, runs)
		}
	}
}

func TestChainRuleActivationKeepsFullIntegerAndRejectsUnsupportedInputs(t *testing.T) {
	for _, value := range []string{"0", "1", "18446744073709551616", "340282366920938463463374607431768211456"} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: value}
		s, err := newSimulation(sc)
		if err != nil {
			t.Fatal(value, err)
		}
		for _, node := range s.nodes {
			at, enabled := node.cfg.RuleActivation(types.RejectNumberJump)
			if !enabled || at.String() != value {
				t.Fatal("activation truncated or disabled", value, at, enabled)
			}
		}
	}
	for _, value := range []string{"", "-1", "+1", "01", "1.0", "1e2", "null", `"1"`, " 1", "{}", "[]"} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: value}
		if _, err := newSimulation(sc); err == nil {
			t.Fatal("invalid activation admitted", value)
		}
	}
	sc := timingCompatibilityScenario(t, 2)
	sc.Params.RuleActivations = map[types.RuleName]string{"unsupported_rule": "0"}
	if _, err := newSimulation(sc); err == nil {
		t.Fatal("official parser did not refuse unknown rule")
	}
}

func TestAbsentChainRulesKeepEntireDefaultRunAndParameterJSON(t *testing.T) {
	sc := timingCompatibilityScenario(t, 7)
	want, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	sc.Params.RuleActivations = map[types.RuleName]string{}
	got, err := Run(context.Background(), sc, Output{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("empty rules changed default output or journals", err)
	}
	raw, err := json.Marshal(sc.Params)
	if err != nil || strings.Contains(string(raw), "RuleActivations") || strings.Contains(string(raw), "AllowedFutureBlockTime") {
		t.Fatal("empty rule declaration changed parameter JSON", string(raw), err)
	}
	base := Params{RuleActivations: map[types.RuleName]string{types.RejectNumberJump: "0"}, AllowedFutureBlockTime: timingValue(3)}
	resolved, err := ResolveTiming(base, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	delete(resolved.RuleActivations, types.RejectNumberJump)
	*resolved.AllowedFutureBlockTime = 99
	if base.RuleActivations[types.RejectNumberJump] != "0" {
		t.Fatal("nil timing override failed to snapshot rule declaration")
	}
	if *base.AllowedFutureBlockTime != 3 {
		t.Fatal("nil timing override failed to snapshot future-block allowance")
	}
}

func TestFutureBlockAllowanceKeepsExplicitZeroAndFullUint64(t *testing.T) {
	for _, value := range []uint64{0, 3, ^uint64(0)} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Params.AllowedFutureBlockTime = timingValue(value)
		s, err := newSimulation(sc)
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range s.nodes {
			if node.cfg.ConfigAt(types.HeightFromUint64(1)).AllowedFutureBlockTime != value {
				t.Fatal("future-block allowance was truncated or defaulted", value)
			}
		}
	}
}
