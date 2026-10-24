package transport

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
	"testing"
)

type preparationSourceTrace struct {
	receiveSourceTrace
	after func(ReceiveTransition)
}

func (o *preparationSourceTrace) ObserveReceiveTransition(event ReceiveTransition) {
	o.receiveTransitions.ObserveReceiveTransition(event)
	if o.after != nil {
		o.after(event)
	}
}

func TestReceivePreparationSourceSurvivesUnlockedReentrantObservation(t *testing.T) {
	for _, run := range []string{"original-prepare-writer", ""} {
		trace := &preparationSourceTrace{receiveSourceTrace: receiveSourceTrace{run: run}}
		ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: trace})
		if err != nil {
			t.Fatal(err)
		}
		scope := NewValidationScope()
		in := Inbound{Peer: types.Address{1}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1)}
		trace.after = func(event ReceiveTransition) {
			if event.Action == ReceiveCheckPrepare {
				// A normal later inspection executes after unlock, before Prepare returns.
				// The returned source must still identify the original preparation.
				if !ledger.mu.TryLock() {
					t.Fatal("prepare observer holds the ledger mutex")
				}
				ledger.mu.Unlock()
				ledger.Known(scope, in.Code, in.Payload)
			}
		}
		ticket, decision, source := ledger.PrepareObserved(scope, in, ReceiveOrigin{})
		if decision != ReceiveReserved || source.WriterRun != run || source.Ledger == 0 || source.Sequence == 0 {
			t.Fatal("original preparation source lost", decision, source)
		}
		events := trace.snapshot()
		matched := 0
		for _, e := range events {
			if e.Sequence == source.Sequence {
				if e.Action != ReceiveCheckPrepare || e.Decision != ReceiveReserved || e.Request != source.Sequence {
					t.Fatal("source identifies another call", e)
				}
				matched++
			}
		}
		if matched != 1 || events[len(events)-1].Sequence <= source.Sequence || events[len(events)-1].Action != ReceiveKnownInspect {
			t.Fatal("later inspection did not exercise source boundary", events)
		}
		if _, err := consensus.Recover(codec.Code(in.Code), in.Payload, nil); err != nil {
			t.Fatal(err)
		}
		if ledger.Accept(ticket, in) != ReceiveRegistered {
			t.Fatal("normal signature check could not register")
		}
		trace.run = "later-writer"
		absent, known, lookup := ledger.PrepareObserved(scope, in, ReceiveOrigin{})
		if absent != (ReceiveTicket{}) || known != ReceiveKnown || lookup.WriterRun != run || lookup.Ledger != source.Ledger || lookup.Sequence <= source.Sequence {
			t.Fatal("ticketless known lookup lost identity", known, lookup)
		}
		events = trace.snapshot()
		matched = 0
		for _, e := range events {
			if e.Sequence == lookup.Sequence {
				if e.Action != ReceiveCheckPrepare || e.Decision != ReceiveKnown || !e.Known || e.Request != 0 {
					t.Fatal("known source identifies another operation", e)
				}
				matched++
			}
		}
		if matched != 1 || events[len(events)-1].Sequence <= lookup.Sequence {
			t.Fatal("known source was replaced by the later operation")
		}
		scope.Close()
		ledger.Close()
		if source.WriterRun != run || lookup.WriterRun != run {
			t.Fatal("namespace rebound after close")
		}
	}
}

func TestReceivePreparationSourceAbsentAndExhaustedMetadataPreservesChecks(t *testing.T) {
	ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	scope := NewValidationScope()
	in := Inbound{Peer: types.Address{1}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1)}
	ticket, d, source := ledger.PrepareObserved(scope, in, ReceiveOrigin{})
	if d != ReceiveReserved || source != (ReceivePreparationSource{}) {
		t.Fatal("unobserved preparation fabricated metadata", d, source)
	}
	ledger.Cancel(ticket)
	scope.Close()
	if _, d, source := ledger.PrepareObserved(scope, in, ReceiveOrigin{}); d != ReceiveUnavailable || source != (ReceivePreparationSource{}) {
		t.Fatal("inactive check fabricated a source", d, source)
	}
	ledger.Close()
	trace := &receiveSourceTrace{run: "original-exhausted-writer"}
	ledger, err = NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: trace})
	if err != nil {
		t.Fatal(err)
	}
	ledger.traceSequence = ^uint64(0)
	ticket, d, source = ledger.PrepareObserved(NewValidationScope(), in, ReceiveOrigin{})
	if d != ReceiveReserved || source.WriterRun != "original-exhausted-writer" || source.Sequence != 0 || ledger.Pending() != 1 {
		t.Fatal("metadata exhaustion changed normal check ownership", d, source)
	}
	ledger.Cancel(ticket)
	ledger.Close()
}
