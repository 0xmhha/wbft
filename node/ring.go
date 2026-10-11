package node

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/0xmhha/wbft/rpc"
)

// eventRing keeps the most recent event records as written (one JSON line
// each) for wbft_events, at most cap of them, and delivers each record to
// the subscribers (wbft_subscribe).
type eventRing struct {
	mu    sync.Mutex
	cap   int
	lines [][]byte // oldest first
	subs  map[*eventSub]struct{}
}

// eventSub is one subscriber. A record that does not fit in ch is dropped
// and remembered as a gap, delivered before the next record that fits.
type eventSub struct {
	ch     chan json.RawMessage
	match  func(json.RawMessage) bool
	gap    bool
	gapRng rpc.GapRange
}

func newEventRing(capacity int) *eventRing {
	return &eventRing{cap: capacity, subs: map[*eventSub]struct{}{}}
}

// Write implements io.Writer; the event writer writes one record per call.
func (r *eventRing) Write(p []byte) (int, error) {
	line := bytes.Clone(bytes.TrimRight(p, "\n"))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
	if len(r.subs) > 0 {
		var h struct{ Seq uint64 }
		_ = json.Unmarshal(line, &h) // a record without seq counts as 0
		for s := range r.subs {      //wbft:unordered each subscriber is independent
			s.deliver(line, h.Seq)
		}
	}
	return len(p), nil
}

// deliver sends rec (seq) to the subscriber without waiting, a pending gap
// first.
func (s *eventSub) deliver(rec []byte, seq uint64) {
	if s.gap {
		g, _ := json.Marshal(rpc.Gap{Gap: s.gapRng})
		select {
		case s.ch <- g:
			s.gap = false
		default:
			s.gapRng.ToSeq = seq
			return
		}
	}
	if s.match != nil && !s.match(rec) {
		return
	}
	select {
	case s.ch <- rec:
	default:
		s.gap, s.gapRng = true, rpc.GapRange{FromSeq: seq, ToSeq: seq}
	}
}

// subscribe returns a channel of the records written from now on that
// match (all when match is nil), buffering at most buffer of them, and the
// function that ends the subscription and closes the channel.
func (r *eventRing) subscribe(buffer int, match func(json.RawMessage) bool) (<-chan json.RawMessage, func()) {
	s := &eventSub{ch: make(chan json.RawMessage, buffer), match: match}
	r.mu.Lock()
	r.subs[s] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, s)
			r.mu.Unlock()
			close(s.ch)
		})
	}
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
