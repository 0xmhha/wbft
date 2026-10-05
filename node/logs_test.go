package node

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/logcat"
	"github.com/0xmhha/wbft/rpc"
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

// TestLogLevelsRPC reads the settings with wbft_logLevels and changes them
// with admin_wbftSetLogLevels: merge, removal by null, replace, and an
// unknown module or level that changes nothing.
func TestLogLevelsRPC(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	defer stop(t, n)
	srv := httptest.NewServer(rpc.Handler(append(n.APIs(), n.AdminAPIs()...)))
	defer srv.Close()
	call := func(method, params string) (rpc.LogLevels, string) {
		t.Helper()
		resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Result rpc.LogLevels
			Error  *struct{ Message string }
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if out.Error != nil {
			return out.Result, out.Error.Message
		}
		return out.Result, ""
	}
	got, e := call("wbft_logLevels", "[]")
	if e != "" || got.Level != "info" || got.Source != "config" || got.Effective["consensus.round"] != "info" || got.At == "" {
		t.Fatalf("initial %+v %s", got, e)
	}
	got, e = call("admin_wbftSetLogLevels", `[{"level":"warn","modules":{"consensus.round":"trace","mempool":"off"}}]`)
	if e != "" || got.Level != "warn" || got.Modules["consensus.round"] != "trace" || got.Effective["node"] != "warn" || got.Source != "rpc" {
		t.Fatalf("set %+v %s", got, e)
	}
	got, e = call("admin_wbftSetLogLevels", `[{"modules":{"mempool":null}}]`)
	if e != "" || got.Level != "warn" || len(got.Modules) != 1 || got.Modules["consensus.round"] != "trace" {
		t.Fatalf("remove %+v %s", got, e)
	}
	got, e = call("admin_wbftSetLogLevels", `[{"modules":{"wal":"debug"},"replace":true}]`)
	if e != "" || len(got.Modules) != 1 || got.Modules["wal"] != "debug" {
		t.Fatalf("replace %+v %s", got, e)
	}
	for _, bad := range []string{`[{"modules":{"nope":"info"}}]`, `[{"level":"loud"}]`} {
		if _, e := call("admin_wbftSetLogLevels", bad); e == "" {
			t.Fatalf("%s accepted", bad)
		}
	}
	if got, _ := call("wbft_logLevels", "[]"); len(got.Modules) != 1 || got.Modules["wal"] != "debug" || got.Level != "warn" {
		t.Fatalf("a refused request changed the settings: %+v", got)
	}
}
