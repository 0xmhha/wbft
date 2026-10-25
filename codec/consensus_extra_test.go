package codec_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
)

func TestConsensusViewPreservesExplicitCarrierIdentity(t *testing.T) {
	raw, err := os.ReadFile("window/testdata/epoch-header.rlp")
	if err != nil {
		t.Fatal(err)
	}
	h, err := codec.DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), h.Extra...)
	limits := wire.Limits{ExtraBytes: 1 << 20, Proofs: 128, SettlementRows: 128, Validators: 128}
	expected, err := wire.BlockHash(h, limits)
	if err != nil {
		t.Fatal(err)
	}
	if codec.BlockHash(h) != expected {
		t.Fatal("runtime and explicit hash differ")
	}
	if _, err := codec.DecodeExtra(h); err == nil {
		t.Fatal("strict legacy decoder accepted explicit envelope")
	}
	before, err := rlp.ListItems(h.Extra)
	if err != nil {
		t.Fatal(err)
	}
	view, err := codec.DecodeConsensusExtra(h)
	if err != nil {
		t.Fatal(err)
	}
	view.Round = 7
	if err := codec.SetConsensusExtra(h, view); err != nil {
		t.Fatal(err)
	}
	after, err := rlp.ListItems(h.Extra)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 2, 3} {
		if !bytes.Equal(before[index], after[index]) {
			t.Fatal("outer commitment changed")
		}
	}
	if codec.BlockHash(h) != expected {
		t.Fatal("current round changed block identity")
	}
	filtered, err := codec.FilteredHeader(h, 9)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := wire.FilteredHeader(h, 9, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filtered.Extra, explicit.Extra) {
		t.Fatal("filter mismatch")
	}
	decoded, err := codec.DecodeConsensusExtra(h)
	if err != nil || decoded.Round != 7 {
		t.Fatalf("owned view: %v", err)
	}
	h.Extra = original
	again, err := codec.DecodeConsensusExtra(h)
	if err != nil {
		t.Fatal(err)
	}
	if again.Round == 7 {
		t.Fatal("nested input was mutated")
	}
}
