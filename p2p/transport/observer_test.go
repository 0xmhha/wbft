package transport

import (
	"testing"

	"github.com/0xmhha/wbft/types"
)

type closedOnly struct{ got string }

func (o *closedOnly) Received(types.Address, uint64, int, []byte, string) {}
func (o *closedOnly) Wrote(types.Address, uint64, []byte, string)         {}
func (o *closedOnly) Attached(types.Address, string)                      {}
func (o *closedOnly) Closed(_ types.Address, reason string)               { o.got = reason }

type closedWith struct {
	closedOnly
	c Close
}

func (o *closedWith) ClosedWith(_ types.Address, c Close) { o.c = c }

// TestReportClosed passes who closed a stream to an observer that records
// it and only the reason to one that does not; CloseCause keeps the known
// causes and maps any other reason to CloseOther.
func TestReportClosed(t *testing.T) {
	c := Close{By: ClosedBySelf, Cause: CloseQueueOverflow, Reason: "queue_overflow"}
	o := &closedOnly{}
	ReportClosed(o, types.Address{1}, c)
	if o.got != "queue_overflow" {
		t.Fatalf("Closed got %q", o.got)
	}
	w := &closedWith{}
	ReportClosed(w, types.Address{1}, c)
	if w.c != c || w.got != "" {
		t.Fatalf("ClosedWith got %+v, Closed %q", w.c, w.got)
	}
	for reason, want := range map[string]string{CloseEngineStopped: CloseEngineStopped, CloseFrame: CloseFrame, "bye": CloseOther, "": CloseOther} {
		if got := CloseCause(reason); got != want {
			t.Fatalf("CloseCause(%q) = %q, want %q", reason, got, want)
		}
	}
}
