package codec

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

func TestRoundChangeDomainUnsignedNestedOwnSequence(t *testing.T) {
	domain := testDomain(t, 7, 1, types.HeightFromUint64(3))
	changes := []*Message{
		{Code: CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(2)}},
		{Code: CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(3)}},
		{Code: CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(4)}},
	}
	var baseline [][]byte
	for _, outerHeight := range []types.Height{types.HeightFromUint64(2), types.HeightFromUint64(3), types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 100))} {
		// This unsigned container is never encoded, signed or delivered. Its
		// arbitrary outer view is not a claim of consensus certificate validity.
		outer := Message{Code: CodePreprepare, View: types.View{Sequence: outerHeight}, RoundChanges: changes}
		for i, nested := range outer.RoundChanges {
			payload, err := SigningPayloadWithDomain(nested, domain)
			legacy, legacyErr := SigningPayload(nested, false, nil)
			if err != nil || legacyErr != nil || bytes.Equal(payload, legacy) != (i == 0) {
				t.Fatal("nested selection did not use its own full sequence", err)
			}
			if len(baseline) < len(changes) {
				baseline = append(baseline, payload)
			} else if !bytes.Equal(payload, baseline[i]) {
				t.Fatal("outer view changed a nested signature payload")
			}
		}
	}
}

func TestRoundChangeDomainVersionErrorClassification(t *testing.T) {
	raw, err := rlp.Encode([]any{uint64(2), big.NewInt(7), types.Hash{1}, big.NewInt(3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRoundChangeDomain(raw); !errors.Is(err, types.ErrRoundChangeDomainVersion) || !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("unknown profile version not classified", err)
	}
	if _, err := DecodeRoundChangeDomain([]byte{0xc0}); err == nil || errors.Is(err, types.ErrRoundChangeDomainVersion) {
		t.Fatal("malformed profile mislabeled as unsupported version", err)
	}
}
