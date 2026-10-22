package transport

import (
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

type qualifiedWriteTrace struct {
	writeTransitions
	owner *AttemptOwner
	run   string
}

func (s *qualifiedWriteTrace) AttemptOwner() *AttemptOwner { return s.owner }
func (s *qualifiedWriteTrace) CaptureRun() string          { return s.run }

func TestWriteAttemptActualReservationAndOriginalOwner(t *testing.T) {
	for _, run := range []string{"original-write-run", ""} {
		trace := &qualifiedWriteTrace{owner: NewAttemptOwner(), run: run}
		ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: trace})
		if err != nil {
			t.Fatal(err)
		}
		target := WritePeer{Addr: types.Address{7}, Session: NewWriteSession()}
		ticket, d := ledger.Prepare(target, uint64(codec.CodeRoundChange), ledgerNormalMessage(t, 1))
		if d != WriteReserved {
			t.Fatal(d)
		}
		actual := trace.snapshot()
		prepared := actual[len(actual)-1]
		trace.run = "later-writer" // A later name cannot replace original absence.
		a := NewWriteSendAttempt(trace.owner, 9, ticket, event.CauseRetry)
		source, ok := a.WriteSource()
		if run == "" {
			if a != (SendAttempt{}) || ok {
				t.Fatal("late namespace filled original missing source")
			}
		} else {
			if !ok || !a.OwnedBy(trace.owner) || source.WriterRun != run || source.Ledger != prepared.Ledger || source.Request != prepared.Request || a.Cache != 0 || a.Operation != 0 {
				t.Fatal("reservation was guessed or mixed with legacy", source)
			}
			mixed := a
			mixed.Cache, mixed.Operation = 1, 2
			if mixed.OwnedBy(trace.owner) {
				t.Fatal("mixed cache domains accepted")
			}
			if _, ok := mixed.WriteSource(); ok {
				t.Fatal("mixed domain retained a write proof")
			}
		}
		for _, a := range []SendAttempt{NewWriteSendAttempt(NewAttemptOwner(), 1, ticket, ""), NewWriteSendAttempt(trace.owner, 0, ticket, ""), NewWriteSendAttempt(trace.owner, 1, WriteTicket{}, "")} {
			if a != (SendAttempt{}) {
				t.Fatal("unrelated owner or absent ticket fabricated a source")
			}
		}
		ledger.Close()
	}
	ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := ledger.Prepare(WritePeer{Addr: types.Address{7}, Session: NewWriteSession()}, uint64(codec.CodeRoundChange), ledgerNormalMessage(t, 1))
	if NewWriteSendAttempt(NewAttemptOwner(), 1, ticket, "") != (SendAttempt{}) {
		t.Fatal("unrecorded ledger acquired evidence")
	}
}
