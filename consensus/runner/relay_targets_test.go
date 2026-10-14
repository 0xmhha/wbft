package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/event/schema"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestRelayTargetEvidenceKeepsEmptyFilteredCallAndStepOwnership(t *testing.T) {
	self, peer := types.Address{1}, types.Address{2}
	vs, err := validator.NewSet([]types.Address{self, peer}, [][]byte{nil, nil}, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	net := &fakeNet{peers: []types.Address{peer}}
	dedup, err := transport.NewDedup(net, transport.DedupOptions{Self: self})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0xc2, 1, 2}
	var raw bytes.Buffer
	r := &Runner{engineRun: 2, d: Deps{Clock: &manualClock{}, Events: event.NewWriter(&raw, self, "writer"), Transport: dedup}}
	step := &stepCtx{step: 7, outs: []consensus.Output{consensus.Relay{Validators: vs, Code: codec.CodePrepare, Payload: payload}}}
	r.execute(step)
	r.execute(step)
	if len(net.sent) != 1 || !bytes.Equal(net.sent[0].payload, payload) {
		t.Fatal("observation changed relay", net.sent)
	}
	check, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	plans := 0
	sends := 0
	for _, line := range bytes.Split(bytes.TrimSpace(raw.Bytes()), []byte("\n")) {
		if err := check.Validate(line); err != nil {
			t.Fatal(err, string(line))
		}
		var row struct {
			Kind                            event.Kind `json:"kind"`
			Step                            uint64     `json:"step"`
			Engine                          uint64     `json:"engine_run"`
			Index                           uint64     `json:"output_index"`
			Candidates, Targets, Suppressed []string
			Key                             string `json:"dedup_key"`
			Available                       bool   `json:"available"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Kind == event.Send {
			sends++
		}
		if row.Kind == event.RelayTargets {
			plans++
			if row.Step != 7 || row.Engine != 2 || row.Index != 1 || !row.Available || row.Key != codec.DedupKey(payload).Hex() || len(row.Candidates) != 1 {
				t.Fatal(row)
			}
			if plans == 1 && (len(row.Targets) != 1 || len(row.Suppressed) != 0) || plans == 2 && (len(row.Targets) != 0 || len(row.Suppressed) != 1) {
				t.Fatal("filtered call disappeared", row)
			}
		}
	}
	if plans != 2 || sends != 1 {
		t.Fatal(plans, sends)
	}
}
