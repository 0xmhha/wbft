package node

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
)

// TestNodeMetrics: a validator that decides blocks reports its height, its
// own sent messages, the outcomes of its self-delivered messages and its
// finalize calls, also without an event stream configured.
func TestNodeMetrics(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	a.waitHead(t, 3, 20*time.Second)
	stop(t, n)
	got := map[string]float64{}
	samples := map[string]int{}
	for _, f := range n.Metrics().Gather() {
		samples[f.Name] = len(f.Samples)
		for _, s := range f.Samples {
			if f.Kind == "histogram" {
				got[f.Name] += float64(s.Count)
				continue
			}
			got[f.Name] += s.Value
		}
	}
	if got["wbft_consensus_height"] < 3 || got["wbft_messages_total"] == 0 || got["wbft_app_call_seconds"] < 3 {
		t.Fatalf("metrics %v", got)
	}
	// The backlog gauge is read from the core's snapshot: one series.
	// A validator syncs its write-ahead log before it sends its own
	// messages.
	if got["wbft_wal_fsync_seconds"] == 0 {
		t.Fatalf("no fsync observed: %v", got)
	}
	// The validator's seals in the stored headers, counted at each new head.
	if got["wbft_validator_seals_total"] == 0 {
		t.Fatalf("no validator seals: %v", got)
	}
	if samples["wbft_backlog_messages"] != 1 {
		t.Fatalf("backlog gauge: %d series", samples["wbft_backlog_messages"])
	}
}
