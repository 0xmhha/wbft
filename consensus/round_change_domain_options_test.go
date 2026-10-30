package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/types"
)

func TestRoundChangeDomainCheckedOptionsRequireExplicitWitness(t *testing.T) {
	cfg, err := types.ParseChainConfig([]byte(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":100}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateChecked(Options{Config: cfg}); !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("future configured domain accepted without a verified witness", err)
	}
	domain, err := types.DomainForConfig(cfg, types.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Config: cfg, RoundChangeDomain: domain}
	state, err := NewStateChecked(options)
	if err != nil || len(state.TimerGenerations()) != 3 {
		t.Fatal("domain changed the local timer profile", err)
	}
	raw, err := json.Marshal(options)
	if err != nil || bytes.Contains(raw, []byte("RoundChangeDomain")) {
		t.Fatal("private runtime witness was implicitly serialized", err)
	}
	var decoded Options
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RoundChangeDomain != nil {
		t.Fatal("generic options JSON reconstructed a private witness")
	}
	// Configuration itself uses a separate explicit portable projection.
	decoded.Config = cfg
	if _, err := NewStateChecked(decoded); !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("generic options JSON granted a chain witness", err)
	}
}
