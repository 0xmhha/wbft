package node

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/0xmhha/wbft/types"
)

// eventsQueued bounds the event records waiting for the writer goroutine
// (observe.md 1).
const eventsQueued = 65_536

// eventsCloseWait bounds how long Stop waits for the queued event records
// to be written.
const eventsCloseWait = 5 * time.Second

// eventQueue decouples the goroutines that emit events (the consensus
// loop among them) from the event file and the recent records: Write
// queues the encoded record and returns, and one goroutine writes the
// records, in order, to out. When the queue is full the record is
// dropped; before the next record that fits, a dropped record
//
//	{"v":1,"type":"dropped","node":…,"run":…,"count":N,"from_seq":S}
//
// takes the place of the N records from seq S (observe.md 1, inspector
// W-05). A write error of out is reported to failed and does not stop the
// queue.
type eventQueue struct {
	mu      sync.Mutex
	wake    *sync.Cond // records queued, or closed
	idle    *sync.Cond // nothing queued or being written
	lines   [][]byte
	writing int // records the goroutine took and has not written yet
	cap     int
	node    types.Address
	run     string
	dropped uint64 // records dropped since the last dropped record
	from    uint64 // seq of the first of them
	closed  bool

	out     io.Writer
	onDrop  func()
	failed  func(error)
	stopped chan struct{}
}

func newEventQueue(out io.Writer, capacity int, node types.Address, run string, onDrop func(), failed func(error)) *eventQueue {
	q := &eventQueue{cap: capacity, node: node, run: run, out: out, onDrop: onDrop, failed: failed, stopped: make(chan struct{})}
	q.wake, q.idle = sync.NewCond(&q.mu), sync.NewCond(&q.mu)
	go q.loop()
	return q
}

// Write implements io.Writer for event.Writer: one record per call. It
// never waits for out.
func (q *eventQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return len(p), nil
	}
	if len(q.lines) >= q.cap {
		if q.dropped == 0 {
			var h struct{ Seq uint64 }
			_ = json.Unmarshal(p, &h)
			q.from = h.Seq
		}
		q.dropped++
		if q.onDrop != nil {
			q.onDrop()
		}
		return len(p), nil
	}
	q.noteDropped()
	q.lines = append(q.lines, bytes.Clone(p))
	q.wake.Signal()
	return len(p), nil
}

// noteDropped queues the dropped record of the records dropped since the
// last one, if any; q.mu is held.
func (q *eventQueue) noteDropped() {
	if q.dropped == 0 {
		return
	}
	m, _ := json.Marshal(struct {
		V       int           `json:"v"`
		Type    string        `json:"type"`
		Node    types.Address `json:"node"`
		Run     string        `json:"run"`
		Count   uint64        `json:"count"`
		FromSeq uint64        `json:"from_seq"`
	}{1, "dropped", q.node, q.run, q.dropped, q.from})
	q.lines = append(q.lines, append(m, '\n'))
	q.dropped = 0
}

// loop writes the queued records until the queue is closed and empty.
func (q *eventQueue) loop() {
	defer close(q.stopped)
	for {
		q.mu.Lock()
		for len(q.lines) == 0 && !q.closed {
			q.wake.Wait()
		}
		batch := q.lines
		q.lines = nil
		q.writing = len(batch)
		done := q.closed
		q.mu.Unlock()
		for _, l := range batch {
			if _, err := q.out.Write(l); err != nil && q.failed != nil {
				q.failed(err)
			}
		}
		q.mu.Lock()
		q.writing = 0
		if len(q.lines) == 0 {
			q.idle.Broadcast()
		}
		q.mu.Unlock()
		if done && len(batch) == 0 {
			return
		}
	}
}

// Close ends the queue: later writes are discarded, and the goroutine
// writes the records already queued and stops. Close waits for it at most
// wait and reports whether it stopped; when out does not return, the
// goroutine is left to it and its records may be lost.
func (q *eventQueue) Close(wait time.Duration) bool {
	q.mu.Lock()
	if !q.closed {
		q.noteDropped()
		q.closed = true
		q.wake.Signal()
	}
	q.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-q.stopped:
		return true
	case <-t.C:
		return false
	}
}

// flush waits until the records queued so far are written.
func (q *eventQueue) flush() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for (len(q.lines) > 0 || q.writing > 0) && !q.closed {
		q.idle.Wait()
	}
}
