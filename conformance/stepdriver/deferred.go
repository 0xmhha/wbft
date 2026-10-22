package stepdriver

import (
	"strconv"

	"github.com/0xmhha/wbft/observe/journal"
)

func deferredEvidence(reader JournalReader, body []byte) (*journal.DeferredEvidence, error) {
	resolver, _ := reader.(journal.CaptureResolver)
	_, e, err := journal.InspectDeferred(resolver, body)
	return e, err
}

// A verified frame in another writer run does not establish a timestamp in the
// current run's monotonic clock. Timed or reordered execution needs that extra
// boundary; ordinary functional replay continues from the inline bytes.
func deferredReceipt(reader JournalReader, writer string, body []byte) (int64, error) {
	e, err := deferredEvidence(reader, body)
	if err != nil || e.Status != "verified" || e.Origin.Run != writer || e.ReceiptMono == nil {
		return 0, ErrTraceScheduleReservation
	}
	mono, err := strconv.ParseInt(*e.ReceiptMono, 10, 64)
	if err != nil || mono < 0 {
		return 0, ErrTraceScheduleReservation
	}
	return mono, nil
}
