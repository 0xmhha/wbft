package logcat

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// resetModules forgets registered modules and unseals the list (tests only).
func resetModules() {
	modMu.Lock()
	names = names[:numFixed]
	modMu.Unlock()
	sealed.Store(false)
}

func TestParseLevel(t *testing.T) {
	for i, n := range []string{"off", "error", "warn", "info", "debug", "TRACE"} {
		if l, err := ParseLevel(n); err != nil || l != Level(i) {
			t.Fatalf("%s: %v %v", n, l, err)
		}
	}
	if _, err := ParseLevel("verbose"); !errors.Is(err, ErrSettings) {
		t.Fatalf("unknown level: %v", err)
	}
}

// TestApply sets explicit module levels over the base level, refuses an
// unknown module without changing the table, and reports what is in force.
func TestApply(t *testing.T) {
	resetModules()
	l := NewLevels()
	at := time.Unix(100, 0)
	a, err := l.Apply(Settings{Base: LevelWarn, Modules: map[string]Level{"consensus.round": LevelTrace, "mempool": LevelOff}}, "config", at)
	if err != nil {
		t.Fatal(err)
	}
	if a.Effective["consensus.round"] != LevelTrace || a.Effective["mempool"] != LevelOff || a.Effective["node"] != LevelWarn ||
		len(a.Modules) != 2 || a.Source != "config" || !a.At.Equal(at) {
		t.Fatalf("applied %+v", a)
	}
	if _, err := l.Apply(Settings{Base: LevelTrace, Modules: map[string]Level{"consensus.rnd": LevelTrace}}, "rpc", at); !errors.Is(err, ErrSettings) ||
		!strings.Contains(err.Error(), "consensus.rnd") {
		t.Fatalf("unknown module: %v", err)
	}
	if l.Current().Base != LevelWarn {
		t.Fatal("a refused setting changed the table")
	}
}

// TestLogger writes a module's lines at or above its level, with the
// module name, whatever the base handler's own level, and turns a module
// off entirely.
func TestLogger(t *testing.T) {
	resetModules()
	l := NewLevels()
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	if _, err := l.Apply(Settings{Base: LevelWarn, Modules: map[string]Level{"consensus.round": LevelTrace, "mempool": LevelOff}}, "config", time.Time{}); err != nil {
		t.Fatal(err)
	}
	round, node, pool := l.Logger(ConsensusRound, base), l.Logger(Node, base), l.Logger(Mempool, base)
	round.Log(t.Context(), SlogLevelTrace, "round trace")
	node.Info("node info")
	node.Warn("node warn")
	pool.Error("pool error")
	out := buf.String()
	for _, want := range []string{"msg=\"round trace\" module=consensus.round", "msg=\"node warn\" module=node"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, not := range []string{"node info", "pool error"} {
		if strings.Contains(out, not) {
			t.Errorf("%q written:\n%s", not, out)
		}
	}
	// A new table takes effect for loggers already made.
	if _, err := l.Apply(Settings{Base: LevelInfo}, "rpc", time.Time{}); err != nil {
		t.Fatal(err)
	}
	node.Info("node info later")
	if !strings.Contains(buf.String(), "node info later") {
		t.Fatal("a logger kept the old table")
	}
}

// TestLazy evaluates a lazy value only when the line is written.
func TestLazy(t *testing.T) {
	resetModules()
	l := NewLevels()
	var buf bytes.Buffer
	lg := l.Logger(Node, slog.NewTextHandler(&buf, nil))
	calls := 0
	v := Lazy(func() slog.Value { calls++; return slog.StringValue("expensive") })
	lg.Debug("hidden", "v", v)
	lg.Info("shown", "v", v)
	if calls != 1 || !strings.Contains(buf.String(), "v=expensive") {
		t.Fatalf("calls %d, output %q", calls, buf.String())
	}
}

// TestRegister adds a module before the first table and refuses one after.
func TestRegister(t *testing.T) {
	resetModules()
	m, err := Register("sdk.gov")
	if err != nil || m.Name() != "sdk.gov" {
		t.Fatalf("register: %v %v", m, err)
	}
	if again, err := Register("sdk.gov"); err != nil || again != m {
		t.Fatalf("again: %v %v", again, err)
	}
	if _, err := Register("bad name"); !errors.Is(err, ErrSettings) {
		t.Fatalf("bad name: %v", err)
	}
	l := NewLevels()
	if _, err := l.Apply(Settings{Base: LevelInfo, Modules: map[string]Level{"sdk.gov": LevelDebug}}, "config", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Register("sdk.late"); !errors.Is(err, ErrRegisterLate) {
		t.Fatalf("late register: %v", err)
	}
	resetModules()
}

// BenchmarkDisabled measures a log call whose module is below the line's
// level (observe.md 7.1: the cost of a disabled call).
func BenchmarkDisabled(b *testing.B) {
	resetModules()
	l := NewLevels()
	lg := l.Logger(ConsensusMsg, slog.NewTextHandler(&bytes.Buffer{}, nil))
	b.ReportAllocs()
	for b.Loop() {
		lg.Debug("message handled", "code", 0x13, "round", 2)
	}
}
