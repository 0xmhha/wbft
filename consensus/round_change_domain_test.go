package consensus

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// These fixtures sign and recover only within their own declared domain.
// They do not deliver foreign messages, alter signed WALs or run a network.
func TestRoundChangeDomainNormalFullAndNestedRecovery(t *testing.T) {
	h := newHarness(t, 4, -1)
	for _, identity := range []struct {
		id      int64
		genesis byte
	}{{7, 1}, {8, 1}, {7, 2}} {
		for _, activation := range []uint64{10, 11} {
			d, err := types.NewRoundChangeDomain(big.NewInt(identity.id), types.Hash{identity.genesis}, types.HeightFromUint64(activation))
			if err != nil {
				t.Fatal(err)
			}
			sign := func(i int, m *codec.Message) *codec.Message {
				t.Helper()
				body, err := codec.SigningPayloadWithDomain(m, d)
				if err != nil {
					t.Fatal(err)
				}
				m.Signature, err = ecdsa.SignData(body, h.keys[i])
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			view := types.View{Sequence: types.HeightFromUint64(10), Round: types.RoundFromUint64(2)}
			block := h.proposal(1)
			prepared := types.RoundFromUint64(1)
			var prepares []*codec.Message
			var changes []*codec.Message
			for i := 0; i < 3; i++ {
				prepares = append(prepares, h.prepare(i, types.View{Sequence: view.Sequence, Round: prepared}, block))
				changes = append(changes, sign(i, &codec.Message{Code: codec.CodeRoundChange, View: view,
					PreparedRound: &prepared, PreparedDigest: blockHash(block)}))
			}
			messages := []*codec.Message{
				sign(0, &codec.Message{Code: codec.CodeRoundChange, View: view}),
				sign(0, &codec.Message{Code: codec.CodeRoundChange, View: view, PreparedRound: &prepared,
					PreparedDigest: blockHash(block), PreparedBlock: block, Prepares: prepares}),
				sign(0, &codec.Message{Code: codec.CodePreprepare, View: view, Proposal: block, RoundChanges: changes, Prepares: prepares}),
			}
			for _, message := range messages {
				raw := h.encode(message)
				before := sha256.Sum256(raw)
				calls := 0
				verified, err := RecoverWithDomain(message.Code, raw, func(a types.Address, v types.View) bool {
					calls++
					return h.vs.Contains(a) && v.Sequence.Cmp(view.Sequence) == 0
				}, d)
				if err != nil || verified.Source != h.addrs[0] {
					t.Fatal("own-domain full recovery failed", err)
				}
				if calls != 1+len(message.RoundChanges)+len(message.Prepares) {
					t.Fatal("nested membership checks were skipped")
				}
				for i, source := range verified.RoundChangeSources {
					if source != h.addrs[i] {
						t.Fatal("nested round-change used a different domain")
					}
				}
				outer, err := RecoverOuterWithDomain(message.Code, raw, d)
				if err != nil || outer.Source != h.addrs[0] || outer.View.Cmp(view) != 0 {
					t.Fatal("own-domain outer recovery failed", err)
				}
				if sha256.Sum256(raw) != before {
					t.Fatal("recovery changed fixture bytes")
				}
			}
		}
	}
}
