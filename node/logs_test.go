package node

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/logcat"
)

// TestLogSettings starts a node with module levels: it records them in a
// LOG_CONFIG event and a log line written whatever the node module's
// level, logs each module with its name at its own level, applies new
// settings while it runs, and refuses to start with an unknown module.
func TestLogSettings(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	logs, ev := &syncBuffer{}, &syncBuffer{}
	settings := logcat.Settings{Base: logcat.LevelOff, Modules: map[string]logcat.Level{"consensus.round": logcat.LevelTrace}}
	n, err := New(Config{DataDir: "/data", Log: &settings}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key, Events: ev,
		Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.waitHead(t, 2, 20*time.Second)
	if !strings.Contains(ev.String(), `"kind":"LOG_CONFIG","level":"off","modules":{"consensus.round":"trace"},"source":"config"`) {
		t.Fatalf("no LOG_CONFIG event:\n%.2000s", ev.String())
	}
	out := logs.String()
	if !strings.Contains(out, `"msg":"log settings","module":"node","level":"off"`) {
		t.Fatalf("no log settings line:\n%.2000s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.Contains(line, `"module":"consensus.round"`) && !strings.Contains(line, `"msg":"log settings"`) {
			t.Fatalf("a line of a module that is off: %s", line)
		}
	}
	if _, err := n.SetLogLevels(logcat.Settings{Base: logcat.LevelInfo, Modules: map[string]logcat.Level{"nope": logcat.LevelInfo}}, "rpc"); !errors.Is(err, logcat.ErrSettings) {
		t.Fatalf("unknown module at run time: %v", err)
	}
	if _, err := n.SetLogLevels(logcat.Settings{Base: logcat.LevelInfo}, "rpc"); err != nil {
		t.Fatal(err)
	}
	if got := n.LogLevels(); got.Source != "rpc" || got.Base != logcat.LevelInfo || !strings.Contains(ev.String(), `"source":"rpc"`) {
		t.Fatalf("after the rpc change: %+v", got)
	}
	stop(t, n)

	bad := logcat.Settings{Base: logcat.LevelInfo, Modules: map[string]logcat.Level{"consensus.rnd": logcat.LevelTrace}}
	n2, err := New(Config{DataDir: "/data2", Log: &bad}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.Start(context.Background()); !errors.Is(err, ErrStartRefused) {
		t.Fatalf("unknown module at start: %v", err)
	}
}
