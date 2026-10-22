package transport

import "testing"

type receiveSourceTrace struct {
	receiveTransitions
	run string
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
