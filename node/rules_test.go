package node

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestChainRulesReported(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["wbftRules"] = json.RawMessage(`{"consensusRules":{"rejectNumberJump":0}}`)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestApp(raw, genesis)
	var events bytes.Buffer
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), Events: &events})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop(t, n)
	info := (backend{n}).NodeInfo()
	parsed, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if info.RulesDigest != parsed.RulesDigest() || info.RuleActivations[types.RejectNumberJump] != "0" {
		t.Fatalf("node info: %+v", info)
	}
	var start struct {
		Digest      types.Hash                `json:"rules_digest"`
		Activations map[types.RuleName]string `json:"rule_activations"`
	}
	line := bytes.Split(events.Bytes(), []byte{'\n'})[0]
	if err := json.Unmarshal(line, &start); err != nil {
		t.Fatal(err)
	}
	if start.Digest != info.RulesDigest || start.Activations[types.RejectNumberJump] != "0" {
		t.Fatalf("start event: %s", line)
	}
	found := false
	for _, improvement := range info.Improvements {
		if improvement.Name == string(types.RejectNumberJump) && improvement.Source == "chain" {
			found = true
		}
	}
	if !found {
		t.Fatal("active chain rule missing from improvements")
	}
}
