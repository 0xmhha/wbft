package transport

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"testing"
)

type receiveSourceTrace struct {
	receiveTransitions
	run string
}

func TestReceiveTicketAcceptedSourceRetainsOriginalRequest(t *testing.T) {
	for _, run := range []string{"original-receive-ledger", ""} {
		trace := &receiveSourceTrace{run: run}
		ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: trace})
		if err != nil {
			t.Fatal(err)
		}
		scope := NewValidationScope()
		origin := ReceiveOrigin{WriterRun: "original-frame", CaptureID: 1}
		in := Inbound{Peer: types.Address{1}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1), Capture: 1}
		ticket, d := ledger.Prepare(scope, in, origin)
		if d != ReceiveReserved {
			t.Fatal(d)
		}
		core := ReceiveAcceptSource{EngineRun: 1, Step: 2, Output: 3, Via: "direct"}
		source := ticket.AcceptedSource(core)
		events := trace.snapshot()
		prepare := events[len(events)-1]
		if source.LedgerRun != run || source.Ledger != prepare.Ledger || source.Scope != prepare.Scope || source.Request != prepare.Request || source.Origin != origin || source.Core != core {
			t.Fatal("original ticket was guessed or replaced", source)
		}
		trace.run = "later-receive-ledger"
		scope.Close()
		ledger.Close()
		if ticket.AcceptedSource(core) != source {
			t.Fatal("closed request inherited later scope/namespace")
		}
	}
	if (ReceiveTicket{}).AcceptedSource(ReceiveAcceptSource{EngineRun: 1, Step: 2, Output: 3, Via: "direct"}) != (AcceptedInputSource{}) {
		t.Fatal("absent ticket fabricated provenance")
	}
}

func (s *receiveSourceTrace) CaptureRun() string { return s.run }

func TestReceiveLedgerObservationSourceFrozenAtCreation(t *testing.T) {
	for _, run := range []string{"original-receive-writer", ""} {
		observer := &receiveSourceTrace{run: run}
		ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: observer})
		if err != nil {
			t.Fatal(err)
		}
		source := ledger.ObservationSource()
		events := observer.snapshot()
		if len(events) != 1 || source.Ledger == 0 || source.Ledger != events[0].Ledger || source.WriterRun != run {
			t.Fatal("source did not name original traced ledger", source)
		}
		observer.run = "later-receive-writer"
		ledger.Close()
		if ledger.ObservationSource() != source {
			t.Fatal("closed ledger inherited later namespace")
		}
	}
	ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	if ledger.ObservationSource() != (ReceiveLedgerSource{}) || (*ReceiveLedger)(nil).ObservationSource() != (ReceiveLedgerSource{}) {
		t.Fatal("unobserved source fabricated")
	}
}
