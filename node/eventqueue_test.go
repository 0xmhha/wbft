package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

// gate is an io.Writer that holds every write until it is opened, and
// fails the writes of records whose text contains fail.
type gate struct {
	mu   sync.Mutex
	open chan struct{}
	buf  bytes.Buffer
	fail string
}

func (g *gate) Write(p []byte) (int, error) {
	<-g.open
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail != "" && strings.Contains(string(p), g.fail) {
		return 0, errors.New("disk full")
	}
	g.buf.Write(p)
	return len(p), nil
}

// TestEventQueue: while the writer is held, Write does not wait; records
// beyond the capacity are dropped and one dropped record stands for them
// before the next record that fits; the records are written in order;
// Close writes what is queued, reports a final run of drops, and later
// writes are discarded. A failed write is reported and the queue goes on.
func TestEventQueue(t *testing.T) {
	g := &gate{open: make(chan struct{}), fail: `"seq":7,`}
	var drops, fails int
	var mu sync.Mutex
	q := newEventQueue(g, 3, types.Address{0xaa}, "r1", func() { drops++ }, func(error) { mu.Lock(); fails++; mu.Unlock() })
	rec := func(seq int) {
		t.Helper()
		if _, err := fmt.Fprintf(q, `{"v":1,"seq":%d,"kind":"X"}`+"\n", seq); err != nil {
			t.Fatal(err)
		}
	}
	// The goroutine takes seq 0 and waits on the gate; 1..3 fill the
	// queue, 4 and 5 are dropped.
	rec(0)
	for {
		q.mu.Lock()
		taken := q.writing == 1
		q.mu.Unlock()
		if taken {
			break
		}
	}
	for seq := 1; seq <= 5; seq++ {
		rec(seq)
	}
	close(g.open)
	q.flush()
	rec(6) // the dropped record of 4..5, then 6
	rec(7) // fails
	q.flush()
	q.mu.Lock()
	q.cap = 0 // every record from now on is dropped
	q.mu.Unlock()
	rec(8)
	rec(9)
	if !q.Close(time.Second) {
		t.Fatal("Close did not stop the writer")
	}
	rec(10) // discarded
	if drops != 4 {
		t.Fatalf("%d drops, want 4", drops)
	}
	mu.Lock()
	if fails != 1 {
		t.Fatalf("%d failed writes, want 1", fails)
	}
	mu.Unlock()
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(g.buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		if m["type"] == "dropped" {
			got = append(got, fmt.Sprintf("dropped %v from %v", m["count"], m["from_seq"]))
			if m["run"] != "r1" || m["node"] != "0xaa00000000000000000000000000000000000000" || m["v"] != float64(1) {
				t.Fatalf("dropped record %s", l)
			}
			continue
		}
		got = append(got, fmt.Sprint(m["seq"]))
	}
	want := "0 1 2 3 dropped 2 from 4 6 dropped 2 from 8"
	if strings.Join(got, " ") != want {
		t.Fatalf("written %q, want %q", strings.Join(got, " "), want)
	}
}

// TestEventQueueStuckWriter: a writer that never returns does not hold up
// Write, and Close gives up after its wait.
func TestEventQueueStuckWriter(t *testing.T) {
	g := &gate{open: make(chan struct{})} // never opened
	q := newEventQueue(g, 2, types.Address{}, "r", nil, nil)
	for seq := range 5 {
		if _, err := fmt.Fprintf(q, `{"v":1,"seq":%d}`+"\n", seq); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if q.Close(50 * time.Millisecond) {
		t.Fatal("Close reported a stopped writer")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close waited %v", d)
	}
}
