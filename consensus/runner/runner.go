package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/privval"
	"github.com/0xmhha/wbft/transport"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
	"github.com/0xmhha/wbft/wal"
)

// Clock is the runner's source of time. Durations are measured on the
// monotonic clock; the wall clock is read only for the wait of a block
// build request and for records.
type Clock interface {
	Now() time.Time
	Mono() time.Duration
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a timer of a Clock.
type Timer interface {
	// Stop prevents the timer from firing; it reports false if the timer
	// already fired or was stopped.
	Stop() bool
}

type systemClock struct{ start time.Time }

type sysTimer struct{ t *time.Timer }

func (t sysTimer) Stop() bool { return t.t.Stop() }

// SystemClock returns the clock of the operating system.
func SystemClock() Clock { return systemClock{start: time.Now()} }

func (c systemClock) Now() time.Time      { return time.Now() }
func (c systemClock) Mono() time.Duration { return time.Since(c.start) }
func (c systemClock) AfterFunc(d time.Duration, f func()) Timer {
	return sysTimer{time.AfterFunc(d, f)}
}

// Chain answers the core's questions about the application's chain. The
// runner records every answer so that a replay needs no application.
type Chain interface {
	// Head returns the application's canonical head.
	Head() *types.Header
	// ValidatorsAt returns the validator set of block number whose parent
	// has hash parent.
	ValidatorsAt(number types.Height, parent types.Hash) (*validator.Set, error)
	// ValidateProposal verifies a proposal (header.VerifyProposal); a
	// proposal from the future fails with header.ErrFutureBlock and the time
	// to wait.
	ValidateProposal(b *types.Block) (time.Duration, error)
	// IsBadBlock reports whether the block is recorded as bad.
	IsBadBlock(h types.Hash) bool
}

// App is the part of the application the runner drives.
type App interface {
	// ReadyToBuild tells the block builder that a round started and how
	// long to wait before building; done is closed when the core leaves the
	// height. It must not block.
	ReadyToBuild(req consensus.RequestBuild, wait time.Duration, done <-chan struct{})
	// FinalizeBlock imports a decided block with its seals. It is called
	// from the commit goroutine, one block at a time in height order, and
	// is idempotent for a block that is already the head.
	FinalizeBlock(b *types.Block, round types.Round) error
}

// EventSink takes event records; *event.Writer is one.
type EventSink interface {
	Write(r event.Record, at event.Stamp) error
}

// Config configures a Runner.
type Config struct {
	// Core configures the consensus core. Core.Self must be the signer's
	// address, or zero for a node that never signs.
	Core consensus.Options
	// ReplayWAL replays the write-ahead log on Start to restore the lock,
	// the prepared certificate, the sent votes and the round of the height
	// being decided (a restart-safety rule).
	ReplayWAL bool
	// Manual runs no goroutine: the caller drives the runner with Pump.
	// The deterministic simulator uses it.
	Manual bool

	// InboxMessages and InboxBytes bound the receive queue of one peer
	// (defaults 256 and 32 MiB).
	InboxMessages int
	InboxBytes    int64
	// OverflowLimit is the number of dropped messages of one peer within
	// OverflowWindow above which the peer is disconnected (defaults 1000
	// and 10 s), unless every peer overflows.
	OverflowLimit  int
	OverflowWindow time.Duration
	// Workers is the number of receive-check workers (default GOMAXPROCS).
	Workers int
}

// Deps are the runner's collaborators.
type Deps struct {
	Chain Chain
	App   App
	// Transport sends and deduplicates; nil sends nothing.
	Transport *transport.Dedup
	// Net is the transport under Transport, used to disconnect peers; nil
	// disconnects nothing.
	Net transport.Transport
	// Signer signs own messages; nil never signs.
	Signer privval.Signer
	// WAL is the write-ahead log; nil keeps none.
	WAL   *wal.Log
	Clock Clock
	// Events receives the event records; nil drops them.
	Events EventSink
	// Journal receives step and outcome records; nil keeps no journal.
	Journal journal.Writer
	// Synchronising reports whether the application is synchronising the
	// chain; consensus messages that arrive while the engine is stopped are
	// then dropped instead of closing the connection.
	Synchronising func() bool
	// Rand draws the choice between the timer queue and the peer queues and
	// the order of receive checks in manual mode; nil uses math/rand/v2.
	Rand func(n int) int
	// Faults is called at the crash points (builds with wbft_faults).
	Faults faultpoint.Handler
	// Logger logs; nil discards.
	Logger *slog.Logger
}

// Errors of the runner.
var (
	ErrRunning    = errors.New("runner: already running")
	ErrNotRunning = errors.New("runner: not running")
	ErrHalted     = errors.New("runner: consensus halted")
	ErrStartPoint = errors.New("runner: start height is not the head + 1")
)

// queued is one input with where it came from.
type queued struct {
	in  consensus.Input
	via string
}

// Values of the via of journal step records.
const (
	viaInternal = "internal"
	viaApp      = "app"
	viaTimer    = "timer"
	viaPeer     = "peer"
	viaWAL      = "wal"
	viaEngine   = "engine"
)

// ReplayInfo reports the WAL replay of the last Start.
type ReplayInfo struct {
	Records  int    // input records fed to the core
	Stopped  string // why the replay stopped early; "" if it did not
	Replayed bool   // the core continues from the replayed state
}

// Runner drives one consensus core.
type Runner struct {
	cfg Config
	d   Deps
	log *slog.Logger

	// Owned by the consensus goroutine.
	core      *consensus.State
	env       *liveEnv
	engineRun uint64
	step      uint64
	internal  []queued
	lastOwn   map[ownKey][]byte
	buildDone chan struct{}
	buildSeq  types.Height
	boundary  []wal.Position // positions of the last end-of-height records
	floorSkip map[string]bool
	lastGen   [3]uint64
	replay    ReplayInfo

	running atomic.Bool
	snap    atomic.Pointer[consensus.Snapshot]
	halted  atomic.Pointer[error]

	appMu    sync.Mutex // runner.app.mu
	appQ     []queued
	headNote *types.Header // coalesced NewHead

	timers scheduler
	inbox  inbox

	commitMu   sync.Mutex // runner.commit.mu
	commitQ    []commitJob
	commitCond *sync.Cond

	ctlMu    sync.Mutex // serialises Start and Stop
	ctl      chan ctlReq
	notify   chan struct{}
	started  bool
	stopLoop chan struct{}
	loopDone sync.WaitGroup
	randMu   sync.Mutex
}

type ownKey struct {
	code uint64
}

type commitJob struct {
	block *types.Block
	round types.Round
	at    time.Duration
}

// New returns a stopped runner.
func New(cfg Config, d Deps) (*Runner, error) {
	if d.Chain == nil || d.App == nil || d.Clock == nil {
		return nil, fmt.Errorf("runner: Chain, App and Clock are required")
	}
	if d.Signer != nil && d.Signer.Address() != cfg.Core.Self {
		return nil, fmt.Errorf("runner: Core.Self %x is not the signer %x", cfg.Core.Self, d.Signer.Address())
	}
	if d.Signer == nil && cfg.Core.Self != (types.Address{}) {
		return nil, fmt.Errorf("runner: Core.Self is set without a signer")
	}
	if cfg.InboxMessages <= 0 {
		cfg.InboxMessages = 256
	}
	if cfg.InboxBytes <= 0 {
		cfg.InboxBytes = 32 << 20
	}
	if cfg.OverflowLimit <= 0 {
		cfg.OverflowLimit = 1000
	}
	if cfg.OverflowWindow <= 0 {
		cfg.OverflowWindow = 10 * time.Second
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0)
	}
	if d.Rand == nil {
		d.Rand = rand.IntN
	}
	lg := d.Logger
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	r := &Runner{cfg: cfg, d: d, log: lg, notify: make(chan struct{}, 1), floorSkip: map[string]bool{}}
	r.timers.r = r
	r.inbox.init(r)
	r.commitCond = sync.NewCond(&r.commitMu)
	r.snap.Store(&consensus.Snapshot{})
	return r, nil
}

func (r *Runner) rand(n int) int {
	r.randMu.Lock()
	defer r.randMu.Unlock()
	return r.d.Rand(n)
}

// wake tells the consensus goroutine that an input is waiting.
func (r *Runner) wake() {
	if r.cfg.Manual {
		return
	}
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Snapshot returns the summary the consensus goroutine published last.
func (r *Runner) Snapshot() *consensus.Snapshot { return r.snap.Load() }

// Running reports whether the engine runs.
func (r *Runner) Running() bool { return r.running.Load() }

// Halted returns the error that halted consensus, or nil.
func (r *Runner) Halted() error {
	if p := r.halted.Load(); p != nil {
		return *p
	}
	return nil
}

// LastReplay reports the WAL replay of the last Start.
func (r *Runner) LastReplay() ReplayInfo { return r.replay }

// Vars returns the state variables of the core (tests and simulation).
// It must be called from the goroutine that drives a manual runner.
func (r *Runner) Vars() *consensus.Vars {
	if r.core == nil {
		return nil
	}
	return r.core.Vars()
}

// EngineRun returns the number of the current engine run.
func (r *Runner) EngineRun() uint64 { return r.engineRun }

func (r *Runner) halt(err error) {
	e := fmt.Errorf("%w: %v", ErrHalted, err)
	if r.halted.CompareAndSwap(nil, &e) {
		r.log.Error("consensus halted", "err", err)
		r.emit(event.Record{Kind: event.Health, Fields: map[string]any{"what": "consensus_halted", "error": err.Error()}}, nil)
	}
}

// Submit hands a proposal of the block builder to the core.
func (r *Runner) Submit(b *types.Block) {
	r.appMu.Lock()
	r.appQ = append(r.appQ, queued{in: consensus.Request{Block: b}, via: viaApp})
	r.appMu.Unlock()
	r.emit(event.Record{Kind: event.ProposalSubmitted, Fields: map[string]any{"number": b.Header.Number.String()}}, nil)
	r.wake()
}

// NewHead reports that the application's head changed. Notifications that
// arrive before the core handles the previous one are coalesced: the core
// sees the latest head.
func (r *Runner) NewHead(h *types.Header) {
	r.appMu.Lock()
	if r.headNote == nil {
		r.appQ = append(r.appQ, queued{in: consensus.NewHead{}, via: viaApp})
	}
	r.headNote = h
	r.appMu.Unlock()
	r.wake()
}

// PeerConnected reports that a validator peer (re)connected.
func (r *Runner) PeerConnected(a types.Address) {
	r.appMu.Lock()
	r.appQ = append(r.appQ, queued{in: consensus.PeerConnected{Addr: a}, via: viaApp})
	r.appMu.Unlock()
	r.wake()
}

// Start starts the engine at height from, which must be the application's
// head + 1. With ReplayWAL it first replays the write-ahead log records of
// that height (restoring the lock, the prepared certificate, the sent votes
// and the round), re-arms the live timers and sends the last own messages of
// the current view again.
func (r *Runner) Start(ctx context.Context, from types.Height) error {
	r.ctlMu.Lock()
	defer r.ctlMu.Unlock()
	if r.running.Load() {
		return ErrRunning
	}
	if err := r.Halted(); err != nil {
		return err
	}
	head := r.d.Chain.Head()
	if head == nil || head.Number.AddUint64(1).Cmp(from) != 0 {
		return ErrStartPoint
	}
	if !r.cfg.Manual && !r.started {
		r.started = true
		r.stopLoop = make(chan struct{})
		r.startGoroutines()
	}
	if r.cfg.Manual {
		return r.startEngine(ctx, head)
	}
	return r.onLoop(func() error { return r.startEngine(ctx, head) })
}

// Stop stops the engine: the core state is discarded, armed timers and
// queued inputs are dropped. A later Start replays the write-ahead log.
func (r *Runner) Stop() error {
	r.ctlMu.Lock()
	defer r.ctlMu.Unlock()
	if !r.running.Load() {
		return ErrNotRunning
	}
	if r.cfg.Manual {
		r.stopEngine("operator")
		return nil
	}
	return r.onLoop(func() error { r.stopEngine("operator"); return nil })
}

// Close stops the engine if it runs and ends the runner's goroutines.
func (r *Runner) Close() error {
	if r.running.Load() {
		_ = r.Stop()
	}
	r.ctlMu.Lock()
	defer r.ctlMu.Unlock()
	if r.started && r.stopLoop != nil {
		close(r.stopLoop)
		r.commitMu.Lock()
		r.commitCond.Broadcast()
		r.commitMu.Unlock()
		r.inbox.mu.Lock()
		r.inbox.cond.Broadcast()
		r.inbox.mu.Unlock()
		r.loopDone.Wait()
		r.stopLoop = nil
	}
	return nil
}

// emit writes an event record; step is the core step it belongs to.
func (r *Runner) emit(rec event.Record, step *uint64) {
	if r.d.Events == nil {
		return
	}
	if err := r.d.Events.Write(rec, event.Stamp{Wall: r.d.Clock.Now(), Mono: r.d.Clock.Mono(), Step: step}); err != nil {
		r.log.Warn("event write failed", "kind", rec.Kind, "err", err)
	}
}
