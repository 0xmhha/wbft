package consensus

import (
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// These locally signed messages exercise ordinary API membership decisions.
// No packet is transmitted and no signature or encoded input is altered.
func TestRecoverWithFailureNormalMembershipContexts(t *testing.T) {
	h := newHarness(t, 4, -1)
	b := h.proposal(1)
	view := types.View{Sequence: b.Header.Number, Round: types.RoundFromUint64(0)}
	prepared := types.RoundFromUint64(0)
	prepares := []*codec.Message{h.prepare(0, view, b), h.prepare(1, view, b), h.prepare(2, view, b)}
	roundChanges := []*codec.Message{h.roundChange(0, types.View{Sequence: view.Sequence, Round: types.RoundFromUint64(1)}, &prepared, b, prepares)}
	messages := []*codec.Message{
		h.prepare(0, view, b), h.commit(0, view, b),
		h.roundChange(0, view, nil, nil, nil),
		h.roundChange(0, types.View{Sequence: view.Sequence, Round: types.RoundFromUint64(1)}, &prepared, b, prepares),
		h.preprepare(0, view, b, nil, nil),
		h.preprepare(0, types.View{Sequence: view.Sequence, Round: types.RoundFromUint64(1)}, b, roundChanges, prepares),
	}
	for _, message := range messages {
		raw := h.encode(message)
		before := sha256.Sum256(raw)
		var oldChecks, newChecks []types.Address
		old, err := Recover(message.Code, raw, func(a types.Address, _ types.View) bool {
			oldChecks = append(oldChecks, a)
			return h.vs.Contains(a)
		})
		if err != nil {
			t.Fatal(err)
		}
		actual, phase, err := RecoverWithFailure(message.Code, raw, func(a types.Address, _ types.View) bool {
			newChecks = append(newChecks, a)
			return h.vs.Contains(a)
		})
		if err != nil || phase != RecoverySucceeded || !reflect.DeepEqual(old, actual) || !reflect.DeepEqual(oldChecks, newChecks) {
			t.Fatalf("normal recovery changed: phase=%d err=%v", phase, err)
		}
		if len(newChecks) != 1+len(message.RoundChanges)+len(message.Prepares) {
			t.Fatal("normal recovery skipped or repeated a signature check")
		}
		checks := 0
		member := func(types.Address, types.View) bool { checks++; return false }
		if v, err := Recover(message.Code, raw, member); v != nil || err != ecdsa.ErrUnauthorizedAddress {
			t.Fatal("legacy API changed its membership error identity")
		}
		checks = 0
		v, phase, err := RecoverWithFailure(message.Code, raw, member)
		if v != nil || phase != RecoveryMembership || err != ecdsa.ErrUnauthorizedAddress || checks != 1 {
			t.Fatalf("membership was confused with cryptographic validity: phase=%d checks=%d err=%v", phase, checks, err)
		}
		// Reevaluate the same intact valid input under an authorized context.
		if v, phase, err := RecoverWithFailure(message.Code, raw, func(types.Address, types.View) bool { return true }); err != nil || phase != RecoverySucceeded || v == nil {
			t.Fatal("an earlier membership rejection became signer authority or persisted into another context")
		}
		if sha256.Sum256(raw) != before {
			t.Fatal("membership checks modified the original signed input")
		}
	}
}

func TestRecoverWithFailureNestedMembershipOrder(t *testing.T) {
	h := newHarness(t, 4, -1)
	b := h.proposal(1)
	prepared := types.RoundFromUint64(0)
	initial := types.View{Sequence: b.Header.Number, Round: prepared}
	next := types.View{Sequence: initial.Sequence, Round: types.RoundFromUint64(1)}
	prepares := []*codec.Message{h.prepare(1, initial, b), h.prepare(2, initial, b), h.prepare(3, initial, b)}
	for _, test := range []struct {
		name    string
		message *codec.Message
		checked []types.Address
	}{
		{"round_change_prepare", h.roundChange(0, next, &prepared, b, prepares), []types.Address{h.addrs[0], h.addrs[1]}},
		{"preprepare_round_change", h.preprepare(0, next, b, []*codec.Message{h.roundChange(1, next, &prepared, b, prepares)}, prepares), []types.Address{h.addrs[0], h.addrs[1]}},
		{"preprepare_prepare", h.preprepare(0, next, b, []*codec.Message{h.roundChange(2, next, &prepared, b, prepares)}, prepares), []types.Address{h.addrs[0], h.addrs[2], h.addrs[1]}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := h.encode(test.message)
			before := sha256.Sum256(raw)
			// The signed content is intact; only this local authority predicate differs.
			var checked []types.Address
			v, phase, err := RecoverWithFailure(test.message.Code, raw, func(a types.Address, _ types.View) bool {
				checked = append(checked, a)
				return a != h.addrs[1] && h.vs.Contains(a)
			})
			if v != nil || phase != RecoveryMembership || err != ecdsa.ErrUnauthorizedAddress || !reflect.DeepEqual(checked, test.checked) {
				t.Fatalf("nested failure did not stop at the first rejected member: phase=%d checked=%v err=%v", phase, checked, err)
			}
			if v, phase, err := RecoverWithFailure(test.message.Code, raw, func(a types.Address, _ types.View) bool { return h.vs.Contains(a) }); err != nil || phase != RecoverySucceeded || v == nil {
				t.Fatal("the original authorized nested input no longer passed")
			}
			if sha256.Sum256(raw) != before {
				t.Fatal("nested membership checks altered the signed input")
			}
		})
	}
}
