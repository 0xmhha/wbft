package logcat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is a log level of a module: off, error, warn, info, debug or trace.
type Level int8

// Levels, from the least to the most detailed.
const (
	LevelOff Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var levelNames = [...]string{"off", "error", "warn", "info", "debug", "trace"}

// String returns the name of the level.
func (l Level) String() string {
	if int(l) < len(levelNames) && l >= 0 {
		return levelNames[l]
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// ParseLevel reads a level name.
func ParseLevel(s string) (Level, error) {
	for i, n := range levelNames {
		if strings.EqualFold(s, n) {
			return Level(i), nil
		}
	}
	return 0, fmt.Errorf("%w: level %q (off, error, warn, info, debug, trace)", ErrSettings, s)
}

// SlogLevelTrace is the slog level of trace lines (below slog.LevelDebug).
const SlogLevelTrace = slog.Level(-8)

// slogMin is the lowest slog level a module at l writes.
func (l Level) slogMin() slog.Level {
	switch l {
	case LevelError:
		return slog.LevelError
	case LevelWarn:
		return slog.LevelWarn
	case LevelInfo:
		return slog.LevelInfo
	case LevelDebug:
		return slog.LevelDebug
	case LevelTrace:
		return SlogLevelTrace
	}
	return slog.Level(math.MaxInt32) // off
}

// Module is a log module: a fixed name every log line of one part of the
// node belongs to (observe.md 7.1).
type Module uint16

// The modules of wbft.
const (
	ConsensusRound Module = iota
	ConsensusMsg
	Transport
	Mempool
	WAL
	Journal
	Privval
	Epoch
	Header
	App
	RPC
	Observe
	Node
	numFixed
)

var (
	modMu sync.Mutex
	// names[m] is the name of module m; the fixed ones come first.
	names = []string{"consensus.round", "consensus.msg", "transport", "mempool", "wal", "journal", "privval", "epoch",
		"header", "app", "rpc", "observe", "node"}
	// sealed stops Register once a level table exists.
	sealed atomic.Bool
)

// Errors of the package.
var (
	// ErrSettings reports an unknown module name or level.
	ErrSettings = errors.New("logcat: invalid log settings")
	// ErrRegisterLate reports a Register after a level table was made.
	ErrRegisterLate = errors.New("logcat: modules are registered before the node starts")
)

// Register adds a module of a wbft-sdk module or an application, named
// "sdk.<name>" or "app.<name>" by convention. It must be called before the
// first level table is made (before a node starts); registering a name
// twice returns the same module.
func Register(name string) (Module, error) {
	modMu.Lock()
	defer modMu.Unlock()
	if i := slices.Index(names, name); i >= 0 {
		return Module(i), nil
	}
	if sealed.Load() {
		return 0, fmt.Errorf("%w: %s", ErrRegisterLate, name)
	}
	if name == "" || strings.ContainsAny(name, " =\t\n") {
		return 0, fmt.Errorf("%w: module name %q", ErrSettings, name)
	}
	names = append(names, name)
	return Module(len(names) - 1), nil
}

// Name returns the name of module m.
func (m Module) Name() string {
	modMu.Lock()
	defer modMu.Unlock()
	if int(m) < len(names) {
		return names[m]
	}
	return fmt.Sprintf("module(%d)", int(m))
}

// Modules returns the names of every module, fixed ones first.
func Modules() []string {
	modMu.Lock()
	defer modMu.Unlock()
	return slices.Clone(names)
}

// Settings are the log settings of a node: a base level and the explicit
// levels of some modules (observe.md 7.1, [log] and [log.modules]).
type Settings struct {
	Base    Level
	Modules map[string]Level
}

// Applied is the settings in force: the explicit settings, the effective
// level of every module, where they came from (config or rpc) and when.
type Applied struct {
	Base      Level
	Modules   map[string]Level // explicit entries only
	Effective map[string]Level // every module
	Source    string
	At        time.Time
}

// table is one immutable level table.
type table struct {
	levels  []Level // by module
	applied Applied
}

// Levels is the level table of a node. The zero value is not usable; use
// NewLevels.
type Levels struct {
	cur atomic.Pointer[table]
}

// NewLevels returns a table with every module at info. It seals the module
// list: Register fails afterwards.
func NewLevels() *Levels {
	sealed.Store(true)
	l := &Levels{}
	if _, err := l.Apply(Settings{Base: LevelInfo}, "default", time.Time{}); err != nil {
		panic(err)
	}
	return l
}

// Apply makes a new table from s and installs it. An unknown module name
// changes nothing and returns ErrSettings.
func (l *Levels) Apply(s Settings, source string, at time.Time) (Applied, error) {
	all := Modules()
	if s.Base < LevelOff || s.Base > LevelTrace {
		return Applied{}, fmt.Errorf("%w: base level %d", ErrSettings, s.Base)
	}
	var unknown []string
	for name, lv := range s.Modules { //wbft:unordered checked as a set
		if !slices.Contains(all, name) {
			unknown = append(unknown, name)
		}
		if lv < LevelOff || lv > LevelTrace {
			return Applied{}, fmt.Errorf("%w: level %d of %s", ErrSettings, lv, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Applied{}, fmt.Errorf("%w: unknown modules %s (known: %s)", ErrSettings, strings.Join(unknown, ", "), strings.Join(all, ", "))
	}
	t := &table{levels: make([]Level, len(all)),
		applied: Applied{Base: s.Base, Modules: map[string]Level{}, Effective: map[string]Level{}, Source: source, At: at}}
	for i, name := range all {
		lv, ok := s.Modules[name]
		if ok {
			t.applied.Modules[name] = lv
		} else {
			lv = s.Base
		}
		t.levels[i] = lv
		t.applied.Effective[name] = lv
	}
	l.cur.Store(t)
	return t.applied, nil
}

// Current returns the settings in force.
func (l *Levels) Current() Applied { return l.cur.Load().applied }

// level returns the level of module m in the current table.
func (l *Levels) level(m Module) Level {
	t := l.cur.Load()
	if int(m) < len(t.levels) {
		return t.levels[m]
	}
	return t.applied.Base
}

// Logger returns a logger of module m that writes through base: every line
// carries module=<name>, and lines below the module's current level are
// dropped before a record is made. The table alone decides: base's own
// level is not consulted, so base should accept every level.
func (l *Levels) Logger(m Module, base slog.Handler) *slog.Logger {
	return slog.New(&handler{levels: l, mod: m, next: base.WithAttrs([]slog.Attr{slog.String("module", m.Name())})})
}

type handler struct {
	levels *Levels
	mod    Module
	next   slog.Handler
}

func (h *handler) Enabled(_ context.Context, lv slog.Level) bool {
	return lv >= h.levels.level(h.mod).slogMin()
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	return h.next.Handle(ctx, r)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	return &handler{levels: h.levels, mod: h.mod, next: h.next.WithAttrs(as)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{levels: h.levels, mod: h.mod, next: h.next.WithGroup(name)}
}

// Lazy defers an expensive log value: f runs only when the record is
// written.
func Lazy(f func() slog.Value) slog.LogValuer { return lazy(f) }

type lazy func() slog.Value

func (f lazy) LogValue() slog.Value { return f() }
