package node

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
)

// TestAppEvents puts application records into the node's event stream:
// they are dropped before Start, stamped like the node's own records with
// src "app" while the node runs (also from concurrent goroutines, with
// distinct sequence numbers), and a kind of the node is refused.
func TestAppEvents(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	ev := &syncBuffer{}
	d := Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key, Events: ev}
	n, err := New(Config{DataDir: "/data"}, d)
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	emit := n.AppEvents()
	emit.Emit("APP_BEFORE_START", nil)
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	const writers, each = 4, 25
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				emit.Emit("APP_TEST", map[string]any{"writer": w, "i": i})
			}
		}()
	}
	wg.Wait()
	emit.Emit(event.NewHead, map[string]any{"number": "1"})
	waitEvent(t, ev, `"kind":"SEND"`, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}

	seqs := map[uint64]bool{}
	apps := 0
	for line := range strings.Lines(ev.String()) {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		seq := uint64(r["seq"].(float64))
		if seqs[seq] {
			t.Fatalf("seq %d twice", seq)
		}
		seqs[seq] = true
		switch r["kind"] {
		case "APP_BEFORE_START":
			t.Fatal("a record emitted before Start was written")
		case "APP_TEST":
			apps++
			if r["src"] != event.AppSrc || r["node"] == nil || r["t_wall"] == nil || r["writer"] == nil {
				t.Fatalf("application record %s", line)
			}
		case string(event.NewHead):
			if r["src"] == event.AppSrc {
				t.Fatalf("an application wrote a node kind: %s", line)
			}
		}
	}
	if apps != writers*each {
		t.Fatalf("%d application records, want %d", apps, writers*each)
	}
}
