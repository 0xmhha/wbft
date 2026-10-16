package node

import (
	"context"
	"encoding/json"
	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type startupBoundaryAuthority struct {
	*testApp
	entered, release chan struct{}
	held             atomic.Bool
}

func (a *startupBoundaryAuthority) Snapshot(ctx context.Context, h types.Hash) (*source.AuthoritySnapshot, error) {
	if a.held.CompareAndSwap(false, true) {
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return a.testApp.Snapshot(ctx, h)
}
func TestNodeStartPrecedesConcurrentApplicationEvents(t *testing.T) {
	cfg, g := testGenesis(t, testKey(0))
	a := &startupBoundaryAuthority{testApp: newTestApp(cfg, g), entered: make(chan struct{}), release: make(chan struct{})}
	ev := &syncBuffer{}
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), Events: ev})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	done := make(chan error, 1)
	go func() { done <- n.Start(t.Context()) }()
	select {
	case <-a.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup handshake was not reached")
	}
	n.Consensus().OnNewHead(app.NewHead{Header: g.Header})
	n.AppEvents().Emit("APP_DURING_START", nil)
	close(a.release)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup blocked")
	}
	n.AppEvents().Emit("APP_AFTER_START", nil)
	n.Consensus().OnNewHead(app.NewHead{Header: g.Header})
	if err = n.Stop(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ev.String(), `"kind":"APP_DURING_START"`) {
		t.Fatal("application event escaped the startup boundary")
	}
	if !strings.Contains(ev.String(), `"kind":"APP_AFTER_START"`) || !strings.Contains(ev.String(), `"kind":"NEW_HEAD"`) {
		t.Fatal("events after startup were dropped")
	}
	var first struct {
		Kind event.Kind `json:"kind"`
		Seq  uint64     `json:"seq"`
	}
	line := strings.SplitN(ev.String(), "\n", 2)[0]
	if err = json.Unmarshal([]byte(line), &first); err != nil {
		t.Fatal(err)
	}
	if first.Kind != event.NodeStart || first.Seq != 0 {
		t.Fatalf("run began with %s sequence %d instead of NODE_START sequence zero", first.Kind, first.Seq)
	}
}
