package codec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

func testDomain(t *testing.T, id int64, genesis byte, at types.Height) *types.RoundChangeDomain {
	t.Helper()
	d, err := types.NewRoundChangeDomain(big.NewInt(id), types.Hash{genesis}, at)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRoundChangeDomainPayloadGoldenAndBoundaries(t *testing.T) {
	d := testDomain(t, 7, 1, types.HeightFromUint64(3))
	m := &Message{Code: CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(3), Round: types.RoundFromUint64(1)}}
	p, err := SigningPayloadWithDomain(m, d)
	if err != nil {
		t.Fatal(err)
	}
	want := "f84398776266742f726f756e642d6368616e67652d646f6d61696e0107a001" + strings.Repeat("00", 31) + "86c515c30301c0"
	if hex.EncodeToString(p) != want {
		t.Fatalf("domain wire golden: %x", p)
	}
	for _, seq := range []uint64{2, 3, 4} {
		m.View.Sequence = types.HeightFromUint64(seq)
		legacy, err := SigningPayload(m, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := SigningPayloadWithDomain(m, d)
		if err != nil || bytes.Equal(legacy, selected) != (seq < 3) {
			t.Fatalf("activation at %d: %v", seq, err)
		}
		old, err := SigningPayloadWithDomain(m, nil)
		if err != nil || !bytes.Equal(old, legacy) {
			t.Fatal("nil domain changed legacy bytes")
		}
	}
	if _, err := SigningPayload(m, true, big.NewInt(7)); !errors.Is(err, ErrChainIDPayload) {
		t.Fatal("legacy unsupported API changed")
	}
	if _, err := SigningPayloadWithDomain(m, new(types.RoundChangeDomain)); err == nil {
		t.Fatal("zero context accepted")
	}
}

func TestRoundChangeDomainUnsignedIdentityAndMessageScope(t *testing.T) {
	at := types.MustHeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 80), big.NewInt(3)))
	d := testDomain(t, 7, 1, at)
	m := &Message{Code: CodeRoundChange, View: types.View{Sequence: at, Round: types.RoundFromUint64(2)}}
	for _, prepared := range []bool{false, true} {
		if prepared {
			r := types.RoundFromUint64(1)
			m.PreparedRound, m.PreparedDigest = &r, types.Hash{3}
		}
		base, err := SigningPayloadWithDomain(m, d)
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range []*types.RoundChangeDomain{testDomain(t, 8, 1, at), testDomain(t, 7, 2, at)} {
			p, err := SigningPayloadWithDomain(m, other)
			if err != nil || bytes.Equal(p, base) {
				t.Fatal("unsigned domain identity collapsed", err)
			}
		}
		m.View.Sequence = types.HeightFromUint64(3)
		got, _ := SigningPayloadWithDomain(m, d)
		legacy, _ := SigningPayload(m, false, nil)
		if !bytes.Equal(got, legacy) {
			t.Fatal("full activation was truncated")
		}
		m.View.Sequence = at
	}
	for _, code := range []Code{CodePrepare, CodeCommit} {
		vote := &Message{Code: code, View: m.View, Digest: types.Hash{4}, Seal: []byte{5}}
		got, _ := SigningPayloadWithDomain(vote, d)
		legacy, _ := SigningPayload(vote, false, nil)
		if !bytes.Equal(got, legacy) {
			t.Fatal("other vote payload changed")
		}
	}
}

func TestRoundChangeDomainDeclarationCanonical(t *testing.T) {
	d := testDomain(t, 7, 1, types.HeightFromUint64(3))
	raw, err := EncodeRoundChangeDomain(d)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRoundChangeDomain(raw)
	if err != nil || !decoded.Equal(d) {
		t.Fatal("profile roundtrip failed", err)
	}
	raw[0] = 0
	if !decoded.Equal(d) {
		t.Fatal("decoded profile aliases input")
	}
	for _, b := range [][]byte{raw, {0xc0}, {0x80}} {
		if _, err := DecodeRoundChangeDomain(b); err == nil {
			t.Fatal("malformed unsigned declaration accepted")
		}
	}
	unknown, _ := rlp.Encode(roundChangeDomainRLP{2, big.NewInt(7), types.Hash{1}, big.NewInt(3)})
	if _, err := DecodeRoundChangeDomain(unknown); !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("unknown domain version accepted", err)
	}
	if got, err := EncodeRoundChangeDomain(nil); err != nil || len(got) != 0 {
		t.Fatal("nil profile added bytes")
	}
}
