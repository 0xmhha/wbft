package stepdriver

import (
	"errors"
	"github.com/0xmhha/wbft/observe/journal"
	"io"
	"testing"
)

type coverageReader struct {
	records []journal.Record
	index   int
}

func (r *coverageReader) Next() (journal.Record, error) {
	if r.index == len(r.records) {
		return journal.Record{}, io.EOF
	}
	v := r.records[r.index]
	r.index++
	return v, nil
}
func TestTraceRejectsJournalLossBeforeClaimingMatch(t *testing.T) {
	r := &coverageReader{records: []journal.Record{{Kind: journal.KindGap, JSeq: 1, Body: &journal.GapRec{Dropped: 1}}}}
	emitted := 0
	e := RunTrace(r, TraceOptions{}, func(StepResult) error { emitted++; return nil })
	if !errors.Is(e, ErrTraceGap) || emitted != 0 {
		t.Fatal("lost input accepted", e, emitted)
	}
}
