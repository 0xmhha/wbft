package node

import (
	"fmt"
	"testing"
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
