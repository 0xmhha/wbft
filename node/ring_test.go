package node

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/rpc"
)

// TestEventRing keeps the most recent records and returns those from a seq
// on, oldest first, at most the limit.
func TestEventRing(t *testing.T) {
	r := newEventRing(3)
	for seq := range 5 {
		if _, err := fmt.Fprintf(r, `{"v":1,"seq":%d}`+"\n", seq); err != nil {
			t.Fatal(err)
		}
	}
	got := r.since(0, 10) // seq 0 and 1 are gone
	if len(got) != 3 || string(got[0]) != `{"v":1,"seq":2}` || string(got[2]) != `{"v":1,"seq":4}` {
		t.Fatalf("since 0: %s", got)
	}
	if got := r.since(3, 1); len(got) != 1 || string(got[0]) != `{"v":1,"seq":3}` {
		t.Fatalf("since 3, limit 1: %s", got)
	}
	if got := r.since(9, 10); len(got) != 0 {
		t.Fatalf("since 9: %s", got)
	}
}

// TestEventRingSubscribe delivers the records written after a subscription
// that match, replaces the records a full subscriber misses with one gap
// record, and stops after the subscription ends.
func TestEventRingSubscribe(t *testing.T) {
	r := newEventRing(100)
	write := func(seq int, kind string) {
		t.Helper()
		if _, err := fmt.Fprintf(r, `{"v":1,"seq":%d,"kind":%q}`+"\n", seq, kind); err != nil {
			t.Fatal(err)
		}
	}
	write(0, "NODE_START") // before the subscription
	f := &rpc.EventFilter{Kinds: []string{"ROUND_ENTER"}}
	ch, cancel := r.subscribe(2, f.Match)
	all, cancelAll := r.subscribe(10, nil)
	write(1, "ROUND_ENTER")
	write(2, "HEALTH") // filtered out
	write(3, "ROUND_ENTER")
	write(4, "ROUND_ENTER") // the buffer of 2 is full: 4 and 5 are dropped
	write(5, "HEALTH")
	if got := []string{string(<-ch), string(<-ch)}; got[0] != `{"v":1,"seq":1,"kind":"ROUND_ENTER"}` || got[1] != `{"v":1,"seq":3,"kind":"ROUND_ENTER"}` {
		t.Fatalf("delivered %s", got)
	}
	write(6, "ROUND_ENTER") // the gap, then 6
	if g, rec := string(<-ch), string(<-ch); g != `{"gap":{"fromSeq":4,"toSeq":5}}` || rec != `{"v":1,"seq":6,"kind":"ROUND_ENTER"}` {
		t.Fatalf("after the gap: %s %s", g, rec)
	}
	cancel()
	cancel() // ends once
	write(7, "ROUND_ENTER")
	if _, ok := <-ch; ok {
		t.Fatal("a record after the subscription ended")
	}
	if len(all) != 7 { // seq 1 .. 7, no gap
		t.Fatalf("unfiltered subscriber holds %d records", len(all))
	}
	cancelAll()
	if len(r.subs) != 0 {
		t.Fatalf("%d subscribers left", len(r.subs))
	}
}
