package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"

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
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// Directories and files under Config.DataDir.
const (
	walDir      = "wal"
	evidenceDir = "evidence"
	privvalDir  = "privval"
	stateFile   = "state"
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
	ev       *event.Writer
	evid     *evidence.Store
	r        *runner.Runner
	pool     *mempool.TxPool
	view     *chainView
	floor    *types.Height // the sign floor this start set or kept
	done     chan struct{} // closed by Stop; ends the node's goroutines
	wg       sync.WaitGroup

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
	n := &Node{cfg: cfg, d: d, fs: d.fs, clock: d.clock, snaps: source.NewCache(source.DefaultCacheSize),
		syncWake: make(chan struct{}, 1)}
	if n.fs == nil {
		n.fs = fsys.OS{}
	}
	if n.clock == nil {
		n.clock = runner.SystemClock()
	}
	n.log = d.Logger
	if n.log == nil {
		n.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n.svc = &service{n: n}
	return n, nil
}

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
	n.mu.Lock()
	n.chainCfg = cfg
	n.view = &chainView{a: n.d.App, cfg: cfg, snaps: n.snaps, now: n.clock.Now}
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
	if n.d.Events != nil {
		ev := event.NewWriter(n.d.Events, self, runID)
		n.mu.Lock() // AppEvents reads it from other goroutines
		n.ev = ev
		n.mu.Unlock()
	}
	evid, err := evidence.Open(n.fs, filepath.Join(n.cfg.DataDir, evidenceDir), evidence.Options{Now: n.clock.Now})
	if err != nil {
		return fmt.Errorf("node: evidence store: %w", err)
	}
	n.mu.Lock()
	n.evid = evid
	n.mu.Unlock()
	log, recov, err := wal.Open(n.fs, filepath.Join(n.cfg.DataDir, walDir), wal.Options{KeepHeights: 2})
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
	if n.signer == nil {
		return nil
	}

	// 6. Consensus core.
	var dedup *transport.Dedup
	if n.d.Transport != nil {
		if dedup, err = transport.NewDedup(n.d.Transport, transport.DedupOptions{Self: self}); err != nil {
			return err
		}
	}
	// The sink keeps the evidence records in the store, with or without an
	// event stream.
	sink := &evidenceSink{store: evid, log: n.log}
	if n.ev != nil {
		sink.next = n.ev
	}
	r, err := runner.New(runner.Config{Core: consensus.Options{Config: cfg, Self: self, Improvements: consensus.RestartSafety}, ReplayWAL: true},
		runner.Deps{Chain: n.view, App: &appDriver{a: n.d.App, ctx: n.ctx}, Transport: dedup, Net: n.d.Transport,
			Signer: n.signer, WAL: log, Clock: n.clock, Events: sink, Synchronising: n.synchronising,
			Faults: n.d.faults, Logger: n.log})
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
		limits.Logger = n.log
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
		n.floor = &h
	}
	if !n.cfg.TakeoverGuard || head.Number.IsZero() {
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
	n.floor = &f
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
		"wal_recovery": map[string]any{"records": recov.Records, "torn_bytes": recov.TornBytes, "corrupted": len(recov.Corrupted)}}
	if n.floor != nil {
		f["sign_floor"] = map[string]any{"height": n.floor.String()}
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
