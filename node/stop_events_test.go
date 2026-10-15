package node

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
)

type heldFinalizeApp struct {
	*testApp
	entered, release chan struct{}
	once             sync.Once
}

func (a *heldFinalizeApp) FinalizeBlock(ctx context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	a.once.Do(func() { close(a.entered); <-a.release })
	return a.testApp.FinalizeBlock(ctx, req)
}

func TestNodeStopWaitsForFinalizationBeforeTerminalEvent(t *testing.T) {
	key := testKey(0)
	cfg, g := testGenesis(t, key)
	a := &heldFinalizeApp{testApp: newTestApp(cfg, g), entered: make(chan struct{}), release: make(chan struct{})}
	ev := &syncBuffer{}
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key, Events: ev})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err = n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	var release sync.Once
	unblock := func() { release.Do(func() { close(a.release) }) }
	t.Cleanup(func() { unblock(); stop(t, n) })
	select {
	case <-a.entered:
	case <-time.After(20 * time.Second):
		t.Fatal("finalization did not start")
	}
	lateBuild := n.buildEventEmitter()
	done := make(chan error, 1)
	go func() { done <- n.Stop() }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for n.running() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("Stop did not close admission")
		}
	}
	n.flushEvents()
	if strings.Contains(ev.String(), `"kind":"NODE_STOP"`) {
		t.Error("NODE_STOP preceded an in-flight finalization")
	}
	select {
	case err := <-done:
		t.Fatalf("Stop returned during finalization: %v", err)
	default:
	}
	unblock()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not finish")
	}
	var kinds []event.Kind
	for line := range strings.Lines(ev.String()) {
		var r struct {
			Kind event.Kind `json:"kind"`
		}
		if err = json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, r.Kind)
	}
	if len(kinds) == 0 || kinds[len(kinds)-1] != event.NodeStop {
		t.Fatalf("terminal event was not last: %v", kinds)
	}
	count := 0
	engineStop := -1
	terminal := -1
	for i, k := range kinds {
		if k == event.NodeStop {
			count++
			terminal = i
		}
		if k == event.EngineStop {
			engineStop = i
		}
	}
	if count != 1 || engineStop < 0 || engineStop >= terminal {
		t.Fatalf("shutdown boundaries: %v", kinds)
	}
	before := ev.String()
	if err = n.Stop(); err != nil {
		t.Fatal(err)
	}
	n.AppEvents().Emit("APP_AFTER_STOP", nil)
	lateBuild(event.Record{Kind: event.BuildFinished, Fields: map[string]any{"build_id": "late-build", "number": "1", "status": "height_left"}})
	if before != ev.String() {
		t.Fatal("repeated Stop or late application event changed the closed run")
	}
}

func TestNodeStopWithoutConsensusCore(t *testing.T) {
	for _, output := range []bool{false, true} {
		t.Run(map[bool]string{false: "ring only", true: "event output"}[output], func(t *testing.T) {
			cfg, g := testGenesis(t, testKey(0))
			a := newTestApp(cfg, g)
			ev := &syncBuffer{}
			d := Deps{App: a, Authority: a, fs: fsys.NewMem()}
			if output {
				d.Events = ev
			}
			n, err := New(Config{DataDir: "/data"}, d)
			if err != nil {
				t.Fatal(err)
			}
			a.cons = n.Consensus()
			if err = n.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if n.Runner() != nil {
				t.Fatal("nonvalidator started a consensus runner")
			}
			if err = n.Stop(); err != nil {
				t.Fatal(err)
			}
			if err = n.Stop(); err != nil {
				t.Fatal(err)
			}
			if output {
				var last event.Kind
				stops := 0
				for line := range strings.Lines(ev.String()) {
					var r struct {
						Kind event.Kind `json:"kind"`
					}
					if err = json.Unmarshal([]byte(line), &r); err != nil {
						t.Fatal(err)
					}
					last = r.Kind
					if last == event.NodeStop {
						stops++
					}
				}
				if last != event.NodeStop || stops != 1 {
					t.Fatal("nonvalidator terminal boundary", last, stops)
				}
			}
		})
	}
}
