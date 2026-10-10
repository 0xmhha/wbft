package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/evidence"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/observe/logcat"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// Directories and files under Config.DataDir.
const (
	walDir       = "wal"
	journalDir   = "journal"
	evidenceDir  = "evidence"
	rejectionDir = "rejections"
	privvalDir   = "privval"
	stateFile    = "state"
)

// headPathsKept is how many recent head paths wbft_headerCopy knows, and
// eventsKept how many recent event records wbft_events serves.
const (
	headPathsKept = 8192
	eventsKept    = 10_000
)

// Node is a consensus node: it runs the consensus core for the application
// and offers the application the Consensus service.
type Node struct {
	cfg   Config
	d     Deps
	log   *slog.Logger
	fs    fsys.FS
	clock runner.Clock
	snaps *source.Cache
	svc   *service

	// ctl serialises Start and Stop; mu guards the fields below for short
	// reads and is never held while the application is called.
	ctl      sync.Mutex
	mu       sync.Mutex
	state    lifeState
	ctx      context.Context
	cancel   context.CancelFunc
	chainCfg *types.Config
	info     app.InfoResponse
	signer   *privval.FileSigner
	wal      *wal.Log
	journal  *journal.FileWriter // nil without a journal
	ev       *event.Writer
	evid     *evidence.Store
	rej      *rejection.Store
	paths    *headPaths // the paths of recent heads (wbft_headerCopy)
	metrics  *metrics.Registry
	levels   *logcat.Levels // log levels by module
	logBase  slog.Handler   // where the modules' log lines go
	// eventMetrics derives metrics from the event records.
	eventMetrics *metrics.EventMetrics
	walFsync     *metrics.Histogram // wbft_wal_fsync_seconds
	refusals     *metrics.Counter   // wbft_privval_refusals_total
	cacheMisses  *metrics.Counter   // wbft_authority_cache_misses_total
	valMetrics   *validatorMetrics  // wbft_validator_*
	ring         *eventRing         // the recent event records (wbft_events)
	r            *runner.Runner
	pool         *mempool.TxPool
	view         *chainView
	floor        *types.Height // the sign floor this start set or kept, or the one it cleared
	floorState   string        // set, kept or cleared (consensus-core.md 10.5; NODE_START sign_floor.status as the simulator writes it)
	done         chan struct{} // closed by Stop; ends the node's goroutines
	wg           sync.WaitGroup

	syncMu     sync.Mutex
	syncLatest *app.SyncState // latest unhandled sync notification
	syncWake   chan struct{}
	firstSync  bool // a synchronisation completed in this process
}

type lifeState uint8

const (
	created lifeState = iota
	started
	stopped
)

// New returns a node that is not started.
func New(cfg Config, d Deps) (*Node, error) {
	if d.App == nil || d.Authority == nil {
		return nil, fmt.Errorf("%w: App and Authority are required", ErrConfig)
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("%w: DataDir is required", ErrConfig)
	}
	if _, native := d.Authority.(source.Native); native && !cfg.Standalone {
		return nil, fmt.Errorf("%w: a native authority source runs only in standalone mode", ErrConfig)
	}
	n := &Node{cfg: cfg, d: d, fs: d.fs, clock: d.clock, snaps: source.NewCache(source.DefaultCacheSize), paths: newHeadPaths(headPathsKept), ring: newEventRing(eventsKept),
		syncWake: make(chan struct{}, 1)}
	if n.fs == nil {
		n.fs = fsys.OS{}
	}
	if n.clock == nil {
		n.clock = runner.SystemClock()
	}
	base := slog.Handler(slog.NewTextHandler(io.Discard, nil))
	if d.Logger != nil {
		base = d.Logger.Handler()
	}
	n.logBase, n.levels = base, logcat.NewLevels()
	n.log = n.levels.Logger(logcat.Node, base)
	n.svc = &service{n: n}
	n.metrics = metrics.NewRegistry()
	n.eventMetrics = metrics.NewEventMetrics(n.metrics)
	n.registerStateMetrics()
	n.refusals = n.metrics.Counter("wbft_privval_refusals_total", "Signatures privval refused, sign floor skips included, by message code.", "code")
	n.cacheMisses = n.metrics.Counter("wbft_authority_cache_misses_total",
		"Authority snapshots of a parent missing from the cache, once per parent and verification, by context.", "context")
	n.valMetrics = newValidatorMetrics(n.metrics)
	n.walFsync = n.metrics.Histogram("wbft_wal_fsync_seconds", "Duration of the write-ahead log's fsyncs, by method.", fsyncBuckets, "method")
	return n, nil
}

// Metrics returns the node's metric registry (observe.md 5). The
// application serves it (metrics.Registry.Handler) or reads it (Gather)
// and may register its own metrics in it.
func (n *Node) Metrics() *metrics.Registry { return n.metrics }

// Consensus returns the service the application calls.
func (n *Node) Consensus() app.Consensus { return n.svc }

// Address returns the address of the node key, or the zero address for a
// node without a key. It is known after Start.
func (n *Node) Address() types.Address {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.signer == nil {
		return types.Address{}
	}
	return n.signer.Address()
}

// SignFloor returns the sign floor of the node key and true if one is set.
// It is known after Start.
func (n *Node) SignFloor() (types.Height, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.signer == nil {
		return types.Height{}, false
	}
	return n.signer.SignFloor()
}

// Mempool returns the transaction pool, or nil for a node without an
// admission hook or before Start.
func (n *Node) Mempool() mempool.Pool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pool == nil {
		return nil
	}
	return n.pool
}

// Runner returns the consensus runner, or nil for a node without a key or
// before Start.
func (n *Node) Runner() *runner.Runner {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.r
}

// Start runs the start-up handshake and starts the consensus core:
//
//  1. read the application's Info and check its interface version;
//  2. parse and check the chain configuration;
//  3. open the write-ahead log and the sign state, and set the sign floor
//     of a taken-over key;
//  4. compare the application head with the log and the sign state, and
//     finalize again a decided block the application did not store;
//  5. load the authority snapshot of the head;
//  6. connect the transport and start the core at head + 1.
func (n *Node) Start(ctx context.Context) error {
	n.ctl.Lock()
	defer n.ctl.Unlock()
	n.mu.Lock()
	if n.state != created {
		n.mu.Unlock()
		return fmt.Errorf("%w: node was already started", ErrStartRefused)
	}
	n.state = started
	n.ctx, n.cancel = context.WithCancel(context.WithoutCancel(ctx))
	n.done = make(chan struct{})
	n.mu.Unlock()
	if err := n.start(ctx); err != nil {
		return errors.Join(err, n.close())
	}
	return nil
}

func (n *Node) start(ctx context.Context) error {
	// 0. Log settings: an unknown module refuses the start.
	settings := LogDefaults
	if n.cfg.Log != nil {
		settings = *n.cfg.Log
	}
	if _, err := n.levels.Apply(settings, "config", n.clock.Now()); err != nil {
		return refuse("%v", err)
	}

	// 1. Application info.
	info, err := n.d.App.Info(ctx)
	if err != nil {
		return fmt.Errorf("node: application info: %w", err)
	}
	if !info.SupportsMajor(app.Major) {
		return refuse("the application supports interface versions %v, not %d", info.AppMajors, app.Major)
	}
	n.mu.Lock()
	n.info = info
	n.mu.Unlock()
	head := n.d.App.Head()
	if head == nil {
		return refuse("the application has no head")
	}
	if g := n.d.App.HeaderByNumber(0); g == nil || codec.BlockHash(g) != info.GenesisHash {
		return refuse("the application's block 0 is not its genesis %x", info.GenesisHash)
	}

	// 2. Chain configuration.
	cfg, err := types.ParseChainConfig(info.ChainConfigJSON)
	if err != nil {
		return refuse("%v", err)
	}
	if err := checkChainConfig(cfg); err != nil {
		return err
	}
	if err := types.CheckConsensusRules(info.ChainConfigJSON); err != nil {
		return refuse("%v", err)
	}
	if info.ChainID != nil && cfg.ChainID != nil && info.ChainID.Cmp(cfg.ChainID) != 0 {
		return refuse("chain id %v of the application differs from %v of the chain configuration", info.ChainID, cfg.ChainID)
	}
	rej, err := rejection.Open(n.fs, filepath.Join(n.cfg.DataDir, rejectionDir), rejection.Options{})
	if err != nil {
		return fmt.Errorf("node: rejection store: %w", err)
	}
	n.mu.Lock()
	n.chainCfg = cfg
	n.rej = rej
	n.view = &chainView{a: n.d.App, cfg: cfg, snaps: n.snaps, now: n.clock.Now, rej: rej, log: n.log, misses: n.cacheMisses, emit: n.emit}
	n.valMetrics.attach(n.d.App, n.view.ValidatorsAt, func(h types.Height) time.Duration {
		return time.Duration(cfg.ConfigAt(h).BlockPeriodSeconds) * time.Second //nolint:gosec // seconds of a config
	}, func(h types.Height) uint64 { return cfg.ConfigAt(h).EpochLength })
	n.mu.Unlock()

	runID := n.cfg.RunID
	if runID == "" {
		runID = fmt.Sprintf("run-%d", n.clock.Now().UnixNano())
	}

	// 3. Logs and sign state.
	if n.cfg.KeyFile != "" || n.d.key != nil {
		if err := n.openSigner(head); err != nil {
			return err
		}
	}
	var self types.Address
	if n.signer != nil {
		self = n.signer.Address()
	}
	// The node always writes its events: to the recent records of
	// wbft_events and, when configured, to Deps.Events.
	var out io.Writer = n.ring
	if n.d.Events != nil {
		out = io.MultiWriter(n.d.Events, n.ring)
	}
	ev := event.NewWriter(out, self, runID)
	ev.Observe(n.eventMetrics.Observe)
	ev.Observe(n.valMetrics.observe)
	n.mu.Lock() // AppEvents reads it from other goroutines
	n.ev = ev
	n.mu.Unlock()
	evid, err := evidence.Open(n.fs, filepath.Join(n.cfg.DataDir, evidenceDir), evidence.Options{Now: n.clock.Now})
	if err != nil {
		return fmt.Errorf("node: evidence store: %w", err)
	}
	n.mu.Lock()
	n.evid = evid
	n.mu.Unlock()
	log, recov, err := wal.Open(n.fs, filepath.Join(n.cfg.DataDir, walDir), wal.Options{KeepHeights: 2, Now: n.clock.Now, Synced: n.walSynced})
	if err != nil {
		return fmt.Errorf("node: write-ahead log: %w", err)
	}
	n.wal = log

	// 4. Handshake.
	st, err := runner.InspectWAL(n.fs, filepath.Join(n.cfg.DataDir, walDir))
	if err != nil {
		return fmt.Errorf("node: write-ahead log: %w", err)
	}
	var signHeight *types.Height
	if n.signer != nil {
		if h, ok := n.signer.LastHeight(); ok {
			signHeight = &h
		}
	}
	act, cr, err := runner.Handshake(head.Number, st, signHeight)
	switch act {
	case runner.Refuse:
		return refuse("%v", err)
	case runner.Refinalize:
		if _, err := n.d.App.FinalizeBlock(ctx, app.FinalizeRequest{Block: cr.Block, Round: cr.Round}); err != nil {
			return fmt.Errorf("node: finalize the decided block %v again: %w", cr.Block.Header.Number, err)
		}
		head = n.d.App.Head()
	case runner.StartAfterRollback:
		n.log.Warn("the write-ahead log is one height ahead of the application", "head", head.Number)
	}

	// 5. Authority snapshot of the head.
	headHash := codec.BlockHash(head)
	if _, ok := n.snaps.Get(headHash); !ok {
		s, err := n.d.Authority.Snapshot(ctx, headHash)
		switch {
		case err == nil:
			n.snaps.Put(s)
		case n.signer != nil:
			return refuse("authority snapshot of the head %v: %v", head.Number, err)
		default:
			n.log.Warn("no authority snapshot of the head", "head", head.Number, "err", err)
		}
	}

	if err := n.startPool(ctx); err != nil {
		return err
	}

	n.emit(event.Record{Kind: event.NodeStart, Fields: n.startFields(act, recov)})
	n.logConfig(n.levels.Current())
	if n.signer == nil {
		return nil
	}

	// 6. Consensus core. With a journal, the transport's frames and peer
	// streams are recorded too.
	core := consensus.Options{Config: cfg, Self: self, Improvements: consensus.RestartSafety}
	jw, err := n.openJournal(core, runID)
	if err != nil {
		return err
	}
	var dedup *transport.Dedup
	if n.d.Transport != nil {
		out := n.d.Transport
		var inbound func(types.Address, bool, bool)
		if jw != nil {
			rec := newFrameRecorder(jw, n.clock, n.wireOffset())
			inbound = rec.inbound
			rec.engine = n.engineState
			if o, ok := n.d.Transport.(transport.Observed); ok {
				o.SetFrameObserver(rec)
			}
			out = recordedTransport{Transport: n.d.Transport, rec: rec}
		}
		suppressed := n.metrics.Counter("wbft_send_suppressed_total", "Sends left out because the peer's recent cache holds the message, by cause.", "cause")
		hits := n.metrics.Counter("wbft_dedup_hits_total", "Received messages whose key was already in a dedup cache, by cache (known, peer_recent).", "cache")
		record := inbound
		inbound = func(peer types.Address, known, peerRecent bool) {
			if known {
				hits.Inc("known")
			}
			if peerRecent {
				hits.Inc("peer_recent")
			}
			if record != nil {
				record(peer, known, peerRecent)
			}
		}
		if dedup, err = transport.NewDedup(out, transport.DedupOptions{Self: self,
			Suppressed: func(c event.SendCause) { suppressed.Inc(string(c)) }, Inbound: inbound}); err != nil {
			return err
		}
	}
	// The sink keeps the evidence records in the store, with or without an
	// event stream.
	sink := &evidenceSink{store: evid, log: n.log}
	if n.ev != nil {
		sink.next = n.ev
	}
	deps := runner.Deps{Chain: n.view, App: &appDriver{a: n.d.App, ctx: n.ctx}, Transport: dedup, Net: n.d.Transport,
		Signer: n.signer, WAL: log, Clock: n.clock, Events: sink, Synchronising: n.synchronising,
		Faults: n.d.faults, Logger: n.levels.Logger(logcat.ConsensusRound, n.logBase), ModuleLogger: n.Logger,
		Refused: func(code uint64) { n.refusals.Inc(fmt.Sprintf("%#x", code)) }}
	if jw != nil {
		deps.Journal = jw
	}
	r, err := runner.New(runner.Config{Core: core, ReplayWAL: true}, deps)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.r = r
	n.mu.Unlock()
	if n.d.Transport != nil {
		n.d.Transport.SetReceiver(r.Receiver())
		if pe := n.d.Transport.PeerEvents(); pe != nil {
			n.wg.Add(1)
			go n.peerLoop(pe)
		}
	}
	n.wg.Add(1)
	go n.syncLoop()
	if err := r.Start(ctx, head.Number.AddUint64(1)); err != nil {
		return fmt.Errorf("node: start the consensus core: %w", err)
	}
	return nil
}

// openJournal opens the message journal of a validator unless it is
// disabled. Its segment records carry what rebuilds the core for replay.
func (n *Node) openJournal(core consensus.Options, runID string) (*journal.FileWriter, error) {
	if n.cfg.Journal.Disabled {
		return nil, nil
	}
	opt := journal.DefaultOptions(filepath.Join(n.cfg.DataDir, journalDir))
	opt.FS = n.fs
	if n.cfg.Journal.KeepHeights != 0 {
		opt.KeepHeights = n.cfg.Journal.KeepHeights
	}
	if n.cfg.Journal.MaxBytes != 0 {
		opt.MaxBytes = n.cfg.Journal.MaxBytes
	}
	n.mu.Lock()
	info := n.info
	n.mu.Unlock()
	id := journal.Identity{Self: core.Self, BLSPublicKey: n.signer.BLSPublicKey(), Run: runID, Commit: moduleVersion(),
		ChainID: info.ChainID, GenesisHash: info.GenesisHash, Mode: n.mode(), WireOffset: n.wireOffset(),
		Core: journal.CoreOptions{ChainConfig: info.ChainConfigJSON, Self: core.Self, Improvements: uint64(core.Improvements),
			BacklogLimit: uint64(core.BacklogLimit)}}
	jw, err := journal.Open(opt, id)
	if err != nil {
		return nil, fmt.Errorf("node: message journal: %w", err)
	}
	n.mu.Lock()
	n.journal = jw
	n.mu.Unlock()
	return jw, nil
}

// Logger returns a logger of module m (logcat.Register for application
// modules, before the node is made) that writes where the node's lines go,
// at the level the node's log settings give m.
func (n *Node) Logger(m logcat.Module) *slog.Logger { return n.levels.Logger(m, n.logBase) }

// LogLevels returns the log settings in force.
func (n *Node) LogLevels() logcat.Applied { return n.levels.Current() }

// SetLogLevels applies new log settings while the node runs (source: rpc,
// or config for a reload) and records them; an unknown module changes
// nothing and returns an error.
func (n *Node) SetLogLevels(s logcat.Settings, source string) (logcat.Applied, error) {
	a, err := n.levels.Apply(s, source, n.clock.Now())
	if err != nil {
		return logcat.Applied{}, err
	}
	n.logConfig(a)
	return a, nil
}

// logConfig records the settings in force: a LOG_CONFIG event, and a log
// line written whatever the level of the node module, so that a reader of
// the log alone knows which lines were turned off (observe.md 7.1).
func (n *Node) logConfig(a logcat.Applied) {
	modules := map[string]any{}
	for name, lv := range a.Modules { //wbft:unordered the event writer sorts keys
		modules[name] = lv.String()
	}
	f := map[string]any{"level": a.Base.String(), "modules": modules, "source": a.Source}
	if len(n.cfg.LogUnmapped) > 0 {
		f["unmapped"] = n.cfg.LogUnmapped
	}
	n.emit(event.Record{Kind: event.LogConfig, Fields: f})
	le := logcat.LogConfigEntry()
	r := slog.NewRecord(n.clock.Now(), le.Level, le.Msg, 0)
	// base_level, not level: a JSON line's own level is under "level".
	r.AddAttrs(slog.String("module", le.Module.Name()), slog.String("base_level", a.Base.String()), slog.Any("modules", modules),
		slog.String("source", a.Source))
	if len(n.cfg.LogUnmapped) > 0 {
		r.AddAttrs(slog.Any("unmapped", n.cfg.LogUnmapped))
	}
	_ = n.logBase.Handle(context.Background(), r)
}

// engineState is the state of the consensus engine as the frame dump
// records it: running, syncing (stopped while the application
// synchronises) or stopped.
func (n *Node) engineState() string {
	if r := n.Runner(); r != nil && r.Running() {
		return "running"
	}
	if n.synchronising() {
		return "syncing"
	}
	return "stopped"
}

// wireOffset is the offset of the istanbul codes on the wire: 0x10 in
// standalone mode, where the codes follow the devp2p base protocol, and 0 in
// embedded mode (observe.md 2.3).
func (n *Node) wireOffset() uint64 {
	if n.cfg.Standalone {
		return 0x10
	}
	return 0
}

// startPool creates and starts the transaction pool.
func (n *Node) startPool(ctx context.Context) error {
	if n.d.Admission == nil {
		return nil
	}
	reg, err := mempool.NewRegistry(n.d.Orderings...)
	if err != nil {
		return refuse("%v", err)
	}
	name := n.cfg.Mempool.Ordering
	if name == "" {
		name = mempool.FIFO
	}
	policy, err := reg.Get(name)
	if err != nil {
		return refuse("%v", err)
	}
	limits := n.cfg.Mempool.Limits
	if limits.Logger == nil {
		limits.Logger = n.levels.Logger(logcat.Mempool, n.logBase)
	}
	pool, err := mempool.New(limits, n.d.Admission, policy, n.d.TxTransport)
	if err != nil {
		return err
	}
	if err := pool.Start(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	n.pool = pool
	n.mu.Unlock()
	return nil
}

// openSigner opens the sign state and sets the sign floor of a taken-over
// key: with TakeoverGuard, an empty sign state and a head above genesis the
// node signs nothing at head + 1.
func (n *Node) openSigner(head *types.Header) error {
	dir := filepath.Join(n.cfg.DataDir, privvalDir)
	if err := n.fs.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key := n.d.key
	if key == nil {
		raw, err := n.fs.ReadFile(n.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("node: key file: %w", err)
		}
		if key, err = privval.ParseKeyFile(raw); err != nil {
			return fmt.Errorf("node: key file: %w", err)
		}
	}
	s, err := privval.NewKeySigner(n.fs, n.d.faults, key, filepath.Join(dir, stateFile))
	if err != nil {
		return refuse("sign state: %v", err)
	}
	n.mu.Lock()
	n.signer = s
	n.mu.Unlock()
	if h, ok := s.SignFloor(); ok {
		n.floor, n.floorState = &h, "kept"
	}
	if !n.cfg.TakeoverGuard {
		// Without the guard a floor that no signature followed is cleared
		// (consensus-core.md 10.5 3.): the way to restart a network that a
		// takeover of more than F validators halted (node-compat.md 4.4).
		if n.floor == nil {
			return nil
		}
		if err := s.ClearSignFloor(); err != nil {
			if errors.Is(err, privval.ErrSignStateNotEmpty) {
				return nil // a signature was recorded: the floor is below it
			}
			return fmt.Errorf("node: clear sign floor: %w", err)
		}
		n.floorState = "cleared"
		n.log.Warn("sign floor cleared: the takeover guard is off", "floor", n.floor.String())
		return nil
	}
	if head.Number.IsZero() {
		return nil
	}
	if !s.Empty() {
		return nil
	}
	f := head.Number.AddUint64(1)
	if err := s.InitSignFloor(f); err != nil {
		if errors.Is(err, privval.ErrSignStateNotEmpty) {
			n.log.Warn("sign floor not set: the sign state holds a signature")
			return nil
		}
		return fmt.Errorf("node: sign floor: %w", err)
	}
	n.floor, n.floorState = &f, "set"
	return nil
}

// mode is the node's mode as NODE_START and wbft_nodeInfo report it.
func (n *Node) mode() string {
	if n.cfg.Standalone {
		return "standalone"
	}
	return "embedded"
}

// improvements lists the enabled improvements with their source: the core's
// restart-safety rules (the default of every profile) and the execution
// layer's.
func (n *Node) improvements() []rpc.Improvement {
	out := []rpc.Improvement{}
	for _, name := range consensus.RestartSafety.Names() {
		out = append(out, rpc.Improvement{Name: name, Source: "profile"})
	}
	n.mu.Lock()
	app := n.info.AppImprovements
	n.mu.Unlock()
	for _, name := range app {
		out = append(out, rpc.Improvement{Name: name, Source: "app"})
	}
	return out
}

func (n *Node) startFields(act runner.HandshakeAction, recov wal.Recovery) map[string]any {
	f := map[string]any{"impl": "wbft", "mode": n.mode(), "handshake": handshakeName(act), "improvements": n.improvements(),
		"log_profile":  logcat.ProfileID(),
		"wal_recovery": map[string]any{"records": recov.Records, "torn_bytes": recov.TornBytes, "corrupted": len(recov.Corrupted)}}
	f["sign_floor"] = nil
	if n.floor != nil {
		f["sign_floor"] = map[string]any{"height": n.floor.String(), "status": n.floorState}
	}
	f["validator"] = n.signer != nil
	return f
}

func handshakeName(a runner.HandshakeAction) string {
	switch a {
	case runner.StartNormal:
		return "start"
	case runner.Refinalize:
		return "refinalize"
	case runner.StartAfterRollback:
		return "start_after_rollback"
	}
	return "refuse"
}

// Stop stops the core, waits for a FinalizeBlock in progress and closes the
// logs. Notifications after Stop are dropped.
func (n *Node) Stop() error {
	n.ctl.Lock()
	defer n.ctl.Unlock()
	if !n.running() {
		return nil
	}
	n.emit(event.Record{Kind: event.NodeStop, Fields: map[string]any{"reason": "operator"}})
	return n.close()
}

// close ends a started node; n.ctl is held.
func (n *Node) close() error {
	n.mu.Lock()
	n.state = stopped
	r := n.r
	n.mu.Unlock()
	var errs []error
	close(n.done)
	if r != nil {
		errs = append(errs, r.Close())
	}
	n.wg.Wait()
	if n.pool != nil {
		n.pool.Stop()
	}
	n.cancel()
	if n.wal != nil {
		errs = append(errs, n.wal.Close())
	}
	// The core has stopped: no record follows.
	if o, ok := n.d.Transport.(transport.Observed); ok && n.journal != nil {
		o.SetFrameObserver(nil)
	}
	if n.journal != nil {
		errs = append(errs, n.journal.Close())
	}
	return errors.Join(errs...)
}

// running reports whether the node is started and not stopped.
func (n *Node) running() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state == started
}

func (n *Node) emit(r event.Record) {
	if n.ev == nil {
		return
	}
	if err := n.ev.Write(r, event.Stamp{Wall: n.clock.Now(), Mono: n.clock.Mono()}); err != nil {
		n.log.Warn("event write failed", "err", err)
	}
}

// AppEvents returns the channel through which application modules put
// their records into the node's event stream (event.AppEmitter). Records
// emitted before Start, or when the node writes no events, are dropped.
func (n *Node) AppEvents() event.AppEmitter { return appEmitter{n} }

type appEmitter struct{ n *Node }

func (e appEmitter) Emit(kind event.Kind, fields map[string]any) {
	n := e.n
	if event.IsNodeKind(kind) {
		n.log.Warn("application event refused: the kind is the node's", "kind", string(kind))
		return
	}
	n.mu.Lock()
	ev := n.ev
	n.mu.Unlock()
	if ev == nil {
		return
	}
	r := event.Record{Kind: kind, Src: event.AppSrc, Fields: fields}
	if err := ev.Write(r, event.Stamp{Wall: n.clock.Now(), Mono: n.clock.Mono()}); err != nil {
		n.log.Warn("application event write failed", "kind", string(kind), "err", err)
	}
}

// peerLoop tells the core about reconnected peers.
func (n *Node) peerLoop(pe <-chan transport.PeerEvent) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case e, ok := <-pe:
			if !ok {
				return
			}
			if e.Attached {
				n.r.PeerConnected(e.Addr)
			}
		}
	}
}

// synchronising reports whether the application is synchronising.
func (n *Node) synchronising() bool {
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	return n.syncLatest != nil && n.syncLatest.Syncing
}

// syncLoop stops the core while the application synchronises and starts
// it again afterwards. After the first synchronisation of the process that
// completed, the core keeps running (SNET-SYNC-030).
func (n *Node) syncLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case <-n.syncWake:
		}
		n.syncMu.Lock()
		s := n.syncLatest
		first := n.firstSync
		if s != nil && !s.Syncing && s.Success {
			n.firstSync = true
		}
		n.syncMu.Unlock()
		if s == nil {
			continue
		}
		switch {
		case s.Syncing && !first && n.r.Running():
			if err := n.r.Stop(); err != nil {
				n.log.Warn("stop the core for synchronisation", "err", err)
			}
		case !s.Syncing && !n.r.Running():
			head := n.d.App.Head()
			if err := n.r.Start(n.ctx, head.Number.AddUint64(1)); err != nil {
				n.log.Warn("start the core after synchronisation", "err", err)
			}
		}
	}
}

// evidenceSink stores the EVIDENCE records of the core (wbft_evidence) and
// passes every record on to the event stream, if any.
type evidenceSink struct {
	store *evidence.Store
	next  runner.EventSink
	log   *slog.Logger
}

func (s *evidenceSink) Write(r event.Record, at event.Stamp) error {
	if r.Kind == event.Evidence && r.View != nil {
		str := func(k string) string { v, _ := r.Fields[k].(string); return v }
		code, _ := r.Fields["code"].(uint64)
		if err := s.store.Add(evidence.Record{Height: r.View.Seq, Round: r.View.Round, Code: code, Kind: str("evidence_kind"),
			Source: str("source"), DigestA: str("digest_a"), DigestB: str("digest_b"), SigA: str("sig_a"), SigB: str("sig_b"),
			Time: at.Wall}); err != nil {
			s.log.Warn("evidence store write failed", "err", err)
		}
	}
	if s.next == nil {
		return nil
	}
	return s.next.Write(r, at)
}

// fsyncBuckets are the buckets of wbft_wal_fsync_seconds, from 100µs.
var fsyncBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1}

// walSynced records one fsync of the write-ahead log (wal.Options.Synced).
func (n *Node) walSynced(method string, d time.Duration) {
	n.walFsync.Observe(d.Seconds(), method)
}

// registerStateMetrics registers the metrics read from the node's parts
// when the registry is gathered (observe.md 5.1): the pool sizes and the
// bytes waiting in the receive queues.
func (n *Node) registerStateMetrics() {
	n.metrics.GaugeFunc("wbft_mempool_txs", "Pooled transactions by list.", []string{"list"}, func() []metrics.Value {
		s, ok := n.poolSizes()
		if !ok {
			return nil
		}
		return []metrics.Value{{Labels: []string{"executable"}, V: float64(s.ExecTxs)}, {Labels: []string{"queued"}, V: float64(s.QueuedTxs)}}
	})
	n.metrics.GaugeFunc("wbft_mempool_bytes", "Bytes of pooled transactions by list.", []string{"list"}, func() []metrics.Value {
		s, ok := n.poolSizes()
		if !ok {
			return nil
		}
		return []metrics.Value{{Labels: []string{"executable"}, V: float64(s.ExecBytes)}, {Labels: []string{"queued"}, V: float64(s.QueuedBytes)}}
	})
	n.metrics.GaugeFunc("wbft_backlog_messages", "Messages the core keeps for a later view, of all sources.", nil, func() []metrics.Value {
		r := n.Runner()
		if r == nil {
			return nil
		}
		return []metrics.Value{{V: float64(r.Snapshot().Backlog)}}
	})
	n.metrics.GaugeFunc("wbft_peer_inbound_queue_bytes", "Payload bytes waiting in the receive queues of all peers.", nil, func() []metrics.Value {
		r := n.Runner()
		if r == nil {
			return nil
		}
		return []metrics.Value{{V: float64(r.InboundBytes())}}
	})
}

func (n *Node) poolSizes() (mempool.PoolSizes, bool) {
	n.mu.Lock()
	p := n.pool
	n.mu.Unlock()
	if p == nil {
		return mempool.PoolSizes{}, false
	}
	return p.Sizes(), true
}
