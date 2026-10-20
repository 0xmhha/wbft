package types

import (
	"math/big"
	"testing"
)

func TestCheckedProposerPolicy(t *testing.T) {
	for _, raw := range []string{
		`{"anzeon":{"wbft":{}}}`,
		`{"anzeon":{"wbft":{"proposerPolicy":null}}}`,
		`{"anzeon":{"wbft":{"proposerPolicy":0}}}`,
		`{"anzeon":{"wbft":{"proposerPolicy":1}}}`,
	} {
		source, err := ParseChainConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		before := source.Base().ProposerPolicy
		effective, err := source.CheckedProposerPolicy()
		if err != nil || effective.Base().ProposerPolicy == nil {
			t.Fatalf("effective policy: %v", err)
		}
		want := uint64(0)
		if before != nil {
			want = before.ID
		}
		if effective.Base().ProposerPolicy.ID != want || (source.Base().ProposerPolicy == nil) != (before == nil) {
			t.Fatal("policy default changed the source")
		}
	}
	for _, raw := range []string{
		`{"anzeon":{"wbft":{"proposerPolicy":2}}}`,
		`{"anzeon":{"wbft":{"proposerPolicy":18446744073709551615}}}`,
		`{"anzeon":{"wbft":{"proposerPolicy":0}},"transitions":[{"block":4,"proposerPolicy":2}]}`,
	} {
		source, err := ParseChainConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.CheckedProposerPolicy(); err == nil {
			t.Fatal("unsupported explicit policy accepted")
		}
	}
	if _, err := (*Config)(nil).CheckedProposerPolicy(); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

func TestCheckedProposerPolicyCopiesConfiguration(t *testing.T) {
	sticky := Sticky
	source := NewConfig(WBFTParams{EpochLength: 4}, []Transition{{Block: big.NewInt(4), WBFT: &WBFTParams{ProposerPolicy: &sticky}}}, GenesisInit{Validators: []Address{{1}}, BLSPublicKeys: [][]byte{{2}}}, big.NewInt(7))
	effective, err := source.CheckedProposerPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if effective.ConfigAt(HeightFromUint64(4)).ProposerPolicy.ID != Sticky {
		t.Fatal("transition did not override default")
	}
	effective.Init.Validators[0][0] = 9
	effective.Init.BLSPublicKeys[0][0] = 9
	effective.ChainID.SetInt64(9)
	effective.transitions[0].Block.SetInt64(9)
	*effective.transitions[0].WBFT.ProposerPolicy = RoundRobin
	if source.Init.Validators[0][0] != 1 || source.Init.BLSPublicKeys[0][0] != 2 || source.ChainID.Int64() != 7 || source.transitions[0].Block.Int64() != 4 || *source.transitions[0].WBFT.ProposerPolicy != Sticky || source.Base().ProposerPolicy != nil {
		t.Fatal("effective configuration aliases its source")
	}
}
