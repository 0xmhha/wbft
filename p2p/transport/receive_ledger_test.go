package transport

import (
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// These local primitive tests use real normal signature recovery, not a
// physical validator-change network. Packet bytes and signatures are unchanged.
func TestReceiveLedgerNormalCheckScopeAndOrigin(t *testing.T) {
	for _, recording := range []bool{false, true} {
		ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true})
		if err != nil {
			t.Fatal(err)
		}
		first, second := NewValidationScope(), NewValidationScope()
		in := Inbound{Peer: types.Address{7}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1)}
		origin := ReceiveOrigin{}
		if recording {
			in.Capture = 7
			origin = ReceiveOrigin{WriterRun: "first-writer", CaptureID: in.Capture}
		}
		ticket, decision := ledger.Prepare(first, in, origin)
		if decision != ReceiveReserved || ticket.Origin() != origin || ledger.Known(first, in.Code, in.Payload) || ledger.Recent(first, in.Peer, in.Code, in.Payload) {
			t.Fatal("unverified input registered or source changed", decision)
		}
		// Another normal transport copy can be checked while the first is
		// pending. Pending ownership is not proof of authentication.
		copyIn := in
		copyIn.Peer = types.Address{8}
		copyTicket, decision := ledger.Prepare(first, copyIn, origin)
		if decision != ReceiveReserved || ledger.Pending() != 2 {
			t.Fatal("unverified copy suppressed normal delivery", decision)
		}
		if _, err := consensus.Recover(codec.Code(in.Code), in.Payload, nil); err != nil {
			t.Fatal(err)
		}
		if ledger.Accept(ticket, in) != ReceiveRegistered || !ledger.Known(first, in.Code, in.Payload) || !ledger.Recent(first, in.Peer, in.Code, in.Payload) {
			t.Fatal("completed normal verification did not register")
		}
		if _, err := consensus.Recover(codec.Code(copyIn.Code), copyIn.Payload, nil); err != nil {
			t.Fatal(err)
		}
		if ledger.Accept(copyTicket, copyIn) != ReceiveDuplicate || !ledger.Recent(first, copyIn.Peer, in.Code, in.Payload) || ledger.Pending() != 0 {
			t.Fatal("verified duplicate lost its transport or ownership")
		}
		if ticket.Origin() != origin {
			t.Fatal("terminal transition changed original writer/capture")
		}
		late := Inbound{Peer: in.Peer, Code: in.Code, Payload: ledgerNormalMessage(t, 2), Capture: in.Capture}
		lateTicket, decision := ledger.Prepare(first, late, origin)
		if decision != ReceiveReserved {
			t.Fatal(decision)
		}
		// A normal replacement of the checking snapshot retires its workers.
		if _, err := consensus.Recover(codec.Code(late.Code), late.Payload, nil); err != nil {
			t.Fatal(err)
		}
		first.Close()
		if ledger.Accept(lateTicket, late) != ReceiveExpired || ledger.Known(second, late.Code, late.Payload) || ledger.Pending() != 0 {
			t.Fatal("old worker authenticated for a replacement context")
		}
		fresh, decision := ledger.Prepare(second, late, origin)
		if decision != ReceiveReserved {
			t.Fatal("old context blocked a new normal check", decision)
		}
		if _, err := consensus.Recover(codec.Code(late.Code), late.Payload, nil); err != nil {
			t.Fatal(err)
		}
		if ledger.Accept(fresh, late) != ReceiveRegistered || !ledger.Known(second, late.Code, late.Payload) {
			t.Fatal("new context could not verify unchanged normal input")
		}
		ledger.Close()
		replacement, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true})
		if err != nil {
			t.Fatal(err)
		}
		if replacement.Accept(fresh, late) != ReceiveUnavailable || replacement.Known(second, late.Code, late.Payload) {
			t.Fatal("old receiver ownership transferred to a new ledger")
		}
	}
}

func TestReceiveLedgerNormalAbandonedCheck(t *testing.T) {
	ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	scope := NewValidationScope()
	in := Inbound{Peer: types.Address{7}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1)}
	ticket, decision := ledger.Prepare(scope, in, ReceiveOrigin{})
	if decision != ReceiveReserved {
		t.Fatal(decision)
	}
	// Normal cancellation uses no altered packet or injected verification error.
	ledger.Cancel(ticket)
	if ledger.Pending() != 0 || ledger.Known(scope, in.Code, in.Payload) || ledger.Recent(scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("abandoned check registered or retained ownership")
	}
}
