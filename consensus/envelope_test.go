package consensus

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// These are locally signed codec fixtures, not an epoch-transition network.
func TestRecoverOuterNormalMessages(t *testing.T) {
	for _, n := range []int{4, 7, 21} {
		h := newHarness(t, n, -1)
		for _, bits := range []uint{0, 64, 128} {
			number := big.NewInt(2)
			if bits != 0 {
				number.Add(number, new(big.Int).Lsh(big.NewInt(1), bits))
			}
			height := types.MustHeightFromBig(number)
			b := h.proposal(1)
			b.Header.Number = height
			v := func(r uint64) types.View {
				return types.View{Sequence: height, Round: types.RoundFromUint64(r)}
			}
			quorum := 2*n/3 + 1
			ps := make([]*codec.Message, quorum)
			rcs := make([]*codec.Message, quorum)
			prepared := types.RoundFromUint64(1)
			for i := range ps {
				ps[i] = h.prepare(i, v(1), b)
				rcs[i] = h.roundChange(i, v(2), &prepared, b, nil)
			}
			messages := []struct {
				name string
				m    *codec.Message
			}{
				{"prepare", h.prepare(0, v(0), b)},
				{"commit", h.commit(0, v(0), b)},
				{"round_change_empty", h.roundChange(0, v(1), nil, nil, nil)},
				{"round_change_prepared", h.roundChange(0, v(2), &prepared, b, ps)},
				{"preprepare_initial", h.preprepare(0, v(0), b, nil, nil)},
				{"preprepare_justified", h.preprepare(0, v(2), b, rcs, ps)},
			}
			for _, tt := range messages {
				t.Run(fmt.Sprintf("n%d/height%s/%s", n, height.String(), tt.name), func(t *testing.T) {
					checkOuter(t, h, tt.m)
				})
			}
		}
	}
}

func TestRecoverOuterFullRound(t *testing.T) {
	h := newHarness(t, 4, -1)
	b := h.proposal(2)
	for _, bits := range []uint{0, 64, 128} {
		round := big.NewInt(2)
		if bits != 0 {
			round.Add(round, new(big.Int).Lsh(big.NewInt(1), bits))
		}
		r, err := types.RoundFromBig(round)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
			t.Run(fmt.Sprintf("round%s/code%d", r.String(), code), func(t *testing.T) {
				checkOuter(t, h, h.vote(0, code, types.View{Sequence: b.Header.Number, Round: r}, b))
			})
		}
	}
}

func checkOuter(t *testing.T, h *harness, m *codec.Message) {
	t.Helper()
	raw := h.encode(m)
	before := sha256.Sum256(raw)
	e, err := codec.DecodeSignedEnvelope(m.Code, raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.DecodeMessage(m.Code, raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := codec.SigningPayload(decoded, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Code != m.Code || e.View.Cmp(m.View) != 0 || !bytes.Equal(e.SigningPayload, want) || !bytes.Equal(e.Signature, decoded.Signature) {
		t.Fatal("outer signed fields differ from complete decoding")
	}
	outer, err := RecoverOuter(m.Code, raw)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	complete, err := Recover(m.Code, raw, func(a types.Address, v types.View) bool {
		calls++
		return h.vs.Contains(a) && v.Sequence.Cmp(m.View.Sequence) == 0
	})
	if err != nil {
		t.Fatal(err)
	}
	if outer.Code != m.Code || outer.View.Cmp(m.View) != 0 || outer.Source != h.addrs[0] || outer.Source != complete.Source {
		t.Fatal("outer recovery differs from complete recovery")
	}
	if calls != 1+len(m.RoundChanges)+len(m.Prepares) {
		t.Fatal("complete recovery did not check all signers")
	}
	if before != sha256.Sum256(raw) {
		t.Fatal("decoding changed the received payload")
	}
}
