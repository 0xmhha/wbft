package node

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestChainRulesReported(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rules       string
		activations map[types.RuleName]string
		enabled     []string
	}{
		{"number", `{"consensusRules":{"rejectNumberJump":0}}`, map[types.RuleName]string{types.RejectNumberJump: "0"}, []string{"rejectNumberJump"}},
		{"bitmap", `{"consensusRules":{"minimalSealerBitmap":0}}`, map[types.RuleName]string{types.MinimalSealerBitmap: "0"}, []string{"minimalSealerBitmap"}},
		{"both", `{"consensusRules":{"rejectNumberJump":0,"minimalSealerBitmap":0}}`, map[types.RuleName]string{types.RejectNumberJump: "0", types.MinimalSealerBitmap: "0"}, []string{"minimalSealerBitmap", "rejectNumberJump"}},
		{"scheduled", `{"consensusRules":{"minimalSealerBitmap":18446744073709551619}}`, map[types.RuleName]string{types.MinimalSealerBitmap: "18446744073709551619"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey(0)
			raw, genesis := testGenesis(t, key)
			var cfg map[string]json.RawMessage
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			cfg["wbftRules"] = json.RawMessage(tc.rules)
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			app := newTestApp(raw, genesis)
			var events bytes.Buffer
			n, err := New(Config{DataDir: "/data"}, Deps{App: app, Authority: app, fs: fsys.NewMem(), Events: &events})
			if err != nil {
				t.Fatal(err)
			}
			app.cons = n.Consensus()
			if err := n.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			stop(t, n)
			info := (backend{n}).NodeInfo()
			parsed, err := types.ParseChainConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			if info.RulesDigest != parsed.RulesDigest() || !reflect.DeepEqual(info.RuleActivations, tc.activations) {
				t.Fatalf("node rules: %+v", info)
			}
			var start struct {
				Digest      types.Hash                `json:"rules_digest"`
				Activations map[types.RuleName]string `json:"rule_activations"`
			}
			line := bytes.Split(events.Bytes(), []byte{'\n'})[0]
			if err := json.Unmarshal(line, &start); err != nil {
				t.Fatal(err)
			}
			if start.Digest != info.RulesDigest || !reflect.DeepEqual(start.Activations, tc.activations) {
				t.Fatal("start event changed the declared rules")
			}
			enabled := []string{}
			for _, improvement := range info.Improvements {
				if improvement.Source == "chain" {
					enabled = append(enabled, improvement.Name)
				}
			}
			if !reflect.DeepEqual(enabled, tc.enabled) {
				t.Fatalf("enabled chain rules=%v, want %v", enabled, tc.enabled)
			}
		})
	}
}
