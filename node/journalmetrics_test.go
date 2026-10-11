package node

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/metrics"
)

// TestJournalRetention: the span the size limit leaves is a gauge, and a
// span below a day is a warning at most once an hour.
func TestJournalRetention(t *testing.T) {
	r := metrics.NewRegistry()
	var buf bytes.Buffer
	now := time.Unix(1_700_000_000, 0)
	m := newJournalMetrics(r, slog.New(slog.NewTextHandler(&buf, nil)), func() time.Time { return now })
	gauge := func() float64 {
		for _, f := range r.Gather() {
			if f.Name == "wbft_journal_retained_seconds" && len(f.Samples) == 1 {
				return f.Samples[0].Value
			}
		}
		t.Fatal("no wbft_journal_retained_seconds sample")
		return 0
	}
	warnings := func() int { return strings.Count(buf.String(), "keeps less than a day") }

	m.Retained(6 * time.Hour)
	if gauge() != 6*3600 || warnings() != 1 {
		t.Fatalf("6h: gauge %v, warnings %d", gauge(), warnings())
	}
	now = now.Add(30 * time.Minute)
	m.Retained(5 * time.Hour)
	if gauge() != 5*3600 || warnings() != 1 {
		t.Fatalf("again within the hour: gauge %v, warnings %d", gauge(), warnings())
	}
	now = now.Add(time.Hour)
	m.Retained(5 * time.Hour)
	if warnings() != 2 {
		t.Fatalf("an hour later: warnings %d", warnings())
	}
	now = now.Add(2 * time.Hour)
	m.Retained(JournalMinRetention)
	if gauge() != JournalMinRetention.Seconds() || warnings() != 2 {
		t.Fatalf("a day: gauge %v, warnings %d", gauge(), warnings())
	}
}
