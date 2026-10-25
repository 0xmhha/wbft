package node

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
)

func TestObservationConfigurationFullWidthJSON(t *testing.T) {
	full := new(big.Int).Lsh(big.NewInt(1), 128)
	config := ObservationConfig{Policy: window.Config{ChainID: full, GenesisHash: types.Hash{1}, Activation: types.MustHeightFromBig(full), Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20, CheckpointBytes: 2 << 20, AddressRows: 32}, Retention: types.MustHeightFromBig(full), HistoryWalk: 128, ReplayHeaders: 128, WitnessItems: 64, WitnessBytes: 1 << 20, WitnessChecksPerStep: 16}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservationConfig
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	before, err := window.NewRecent(config.Policy, config.Retention)
	if err != nil {
		t.Fatal(err)
	}
	after, err := window.NewRecent(decoded.Policy, decoded.Retention)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest() != after.Digest() || decoded.Retention.Big().Cmp(full) != 0 || decoded.Policy.Activation.Big().Cmp(full) != 0 {
		t.Fatal("full-width policy changed on round trip")
	}
	// These are detached configuration documents, never runtime inputs.
	for _, closed := range []string{
		strings.Replace(string(raw), `"retention":"`+full.String()+`"`, `"retention":"0`+full.String()+`"`, 1),
		strings.Replace(string(raw), `"retention":"`+full.String()+`"`, `"retention":"0"`, 1),
		strings.Replace(string(raw), `"witnessItems":64`, `"witnessItems":0`, 1),
		strings.Replace(string(raw), `"window":2`, `"unknownWindow":2`, 1),
	} {
		if closed == string(raw) {
			t.Fatal("closed document was not changed")
		}
		if err := json.Unmarshal([]byte(closed), &decoded); err == nil {
			t.Fatal("unsupported closed configuration accepted")
		}
	}
}
