package transport

import (
	"crypto/sha256"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

func ledgerNormalMessage(t *testing.T, round uint64) []byte {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = 2
	key, err := ecdsa.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(round)}}
	data, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(data, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := consensus.Recover(m.Code, raw, nil)
	if err != nil || verified.Source != ecdsa.Address(key) {
		t.Fatalf("normal signed fixture: %v", err)
	}
	return raw
}

// This checks the functional ledger against a prefix oracle over normal
// session lifetimes. It is not a claim that these are physical network runs;
// the SDK tests separately exercise actual WriteMsg and completion callbacks.
func TestWriteLedgerNormalCompletionOrders(t *testing.T) {
	const submit1, queued1, wrote1, close1, open2, submit2, queued2, wrote2, close2 = 0, 1, 2, 3, 4, 5, 6, 7, 8
	edges := [][2]int{{submit1, queued1}, {submit1, wrote1}, {submit1, close1}, {close1, open2}, {open2, submit2}, {submit2, queued2}, {submit2, wrote2}, {submit2, close2}}
	raw := [2][]byte{ledgerNormalMessage(t, 1), ledgerNormalMessage(t, 2)}
	code := uint64(codec.CodeRoundChange)
	orders, prefixes, early, late := 0, 0, 0, 0
	var visit func([]int, [9]bool)
	visit = func(order []int, used [9]bool) {
		if len(order) < 9 {
			for next := 0; next < 9; next++ {
				if used[next] {
					continue
				}
				ready := true
				for _, edge := range edges {
					if edge[1] == next && !used[edge[0]] {
						ready = false
					}
				}
				if ready {
					copyUsed := used
					copyUsed[next] = true
					visit(append(append([]int(nil), order...), next), copyUsed)
				}
			}
			return
		}
		ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true})
		if err != nil {
			t.Fatal(err)
		}
		positions := [9]int{}
		for i, event := range order {
			positions[event] = i
		}
		targets := [2]WritePeer{{Addr: types.Address{7}, Session: NewWriteSession()}, {Addr: types.Address{7}}}
		var tickets [2]WriteTicket
		submits, writes, closes := [2]int{submit1, submit2}, [2]int{wrote1, wrote2}, [2]int{close1, close2}
		for i, event := range order {
			switch event {
			case open2:
				targets[1].Session = NewWriteSession()
			case submit1, submit2:
				j := 0
				if event == submit2 {
					j = 1
				}
				var decision WriteDecision
				tickets[j], decision = ledger.Prepare(targets[j], code, raw[j])
				if decision != WriteReserved {
					t.Fatal("normal submission refused", order, event, decision)
				}
			case queued1, queued2:
				j := 0
				if event == queued2 {
					j = 1
				}
				ledger.QueueResult(tickets[j], Queued)
			case wrote1, wrote2:
				j := 0
				if event == wrote2 {
					j = 1
				}
				ledger.Complete(tickets[j], WriteReceipt{Target: targets[j], Code: code, PayloadSHA256: sha256.Sum256(raw[j]), Result: LocalWriteOK})
			case close1:
				targets[0].Session.Close()
			case close2:
				targets[1].Session.Close()
			}
			// The independent oracle uses only event positions. Queue-return
			// ordering never changes completed or outstanding ownership.
			wantPending := uint64(0)
			for j := range 2 {
				if positions[submits[j]] <= i && positions[writes[j]] > i && positions[closes[j]] > i {
					wantPending++
				}
				wantRecent := positions[writes[j]] <= i && positions[writes[j]] < positions[closes[j]]
				if ledger.Recent(types.Address{7}, code, raw[j]) != wantRecent {
					t.Fatal("completed set differs from prefix oracle", order, i, j)
				}
			}
			if ledger.Pending() != wantPending {
				t.Fatal("pending ownership differs from prefix oracle", order, i)
			}
			prefixes++
		}
		for j, queued := range [2]int{queued1, queued2} {
			if positions[writes[j]] < positions[queued] && positions[writes[j]] < positions[closes[j]] {
				early++
			}
			if positions[writes[j]] > positions[closes[j]] {
				late++
			}
		}
		ledger.Close()
		orders++
	}
	visit(nil, [9]bool{})
	if orders != 336 || prefixes != 3024 || early != 154 || late != 456 {
		t.Fatal("normal event-order coverage changed", orders, prefixes, early, late)
	}
	t.Logf("normal_orders=%d prefix_oracles=%d completed_before_queue_return=%d late_after_normal_close=%d", orders, prefixes, early, late)
}
