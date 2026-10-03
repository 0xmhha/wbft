package node

import (
	"bytes"
	"encoding/json"
	"sync"
)

// eventRing keeps the most recent event records as written (one JSON line
// each) for wbft_events, at most cap of them.
type eventRing struct {
	mu    sync.Mutex
	cap   int
	lines [][]byte // oldest first
}

func newEventRing(capacity int) *eventRing { return &eventRing{cap: capacity} }

// Write implements io.Writer; the event writer writes one record per call.
func (r *eventRing) Write(p []byte) (int, error) {
	line := bytes.TrimRight(p, "\n")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, bytes.Clone(line))
	if len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
	return len(p), nil
}

// since returns at most limit records whose seq is at least from, oldest
// first.
func (r *eventRing) since(from uint64, limit int) []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []json.RawMessage{}
	for _, l := range r.lines {
		var h struct{ Seq uint64 }
		if json.Unmarshal(l, &h) != nil || h.Seq < from {
			continue
		}
		out = append(out, json.RawMessage(l))
		if len(out) == limit {
			break
		}
	}
	return out
}
