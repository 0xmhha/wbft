package inputlog

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func TestCommitResultViewBindingRoundTrip(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 130)
	h, err := types.HeightFromBig(huge)
	if err != nil {
		t.Fatal(err)
	}
	r, err := types.RoundFromBig(new(big.Int).Add(huge, big.NewInt(7)))
	if err != nil {
		t.Fatal(err)
	}
	v := types.View{Sequence: h, Round: r}
	for _, cause := range []error{nil, errors.New("ordinary import failure")} {
		in := consensus.CommitResult{Hash: types.Hash{3}, Err: cause, View: &v}
		encoded, err := Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(KindCommitResult, encoded, nil)
		if err != nil {
			t.Fatal(err)
		}
		out := decoded.(consensus.CommitResult)
		if out.View == nil || out.View.Cmp(v) != 0 || out.Hash != in.Hash || (out.Err == nil) != (cause == nil) {
			t.Fatal("view or result changed", out)
		}
		if cause != nil && out.Err.Error() != cause.Error() {
			t.Fatal("failure reason changed")
		}
		again, err := Encode(out)
		if err != nil || !bytes.Equal(encoded, again) {
			t.Fatal("bound record bytes changed", err)
		}
		legacy := consensus.CommitResult{Hash: in.Hash, Err: cause}
		old, err := Encode(legacy)
		if err != nil {
			t.Fatal(err)
		}
		message := ""
		if cause != nil {
			message = cause.Error()
		}
		original, err := rlp.Encode([]any{legacy.Hash, message})
		if err != nil || !bytes.Equal(old, original) {
			t.Fatal("legacy record format changed")
		}
		x, err := Decode(KindCommitResult, old, nil)
		if err != nil || x.(consensus.CommitResult).View != nil {
			t.Fatal("legacy view was invented")
		}
	}
	bad, err := rlp.Encode([]any{types.Hash{}, "", big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(KindCommitResult, bad, nil); !errors.Is(err, ErrDecode) {
		t.Fatal("incomplete binding accepted", err)
	}
}
