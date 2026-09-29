package sim

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Directories in a node's file system.
const (
	walDir     = "/node/wal"
	privvalDir = "/node/privval"
	journalDir = "/node/journal"
)

// crashSignal is the panic value of a fault point that crashes a node.
type crashSignal struct{ point string }

// node is one simulated node: its file system and application outlive its
// incarnations; the runner, the logs and the signer belong to one.
type node struct {
	s         *simulation
	i         int
	v         Validator
	spec      NodeSpec
	fs        *fsys.Mem
	app       *app
	adversary bool

	inc    int
	alive  bool
	down   bool // stopped or crashed by the schedule or a fault
	clock  *nodeClock
	rng    *rand.Rand
	r      *runner.Runner
	signer *privval.FileSigner
	log    *wal.Log
	jw     *journal.FileWriter
	tr     *adapter
	ev     *event.Writer

	eventFiles  map[string]*bytes.Buffer
	faultHits   map[string]int
	pendingLock *lockCheck
}

// lockCheck is the lock of a node that crashed after an own message was
// logged, to compare after its restart.
type lockCheck struct {
	head  uint64
	vars  *consensus.Vars
	point string
}

func newNode(s *simulation, i int, v Validator, spec NodeSpec) *node {
	n := &node{s: s, i: i, v: v, spec: spec, fs: fsys.NewMem(), eventFiles: map[string]*bytes.Buffer{}, faultHits: map[string]int{},
		rng: rand.New(rand.NewPCG(uint64(s.sc.Seed), uint64(i)+1))}
	n.app = newApp(n)
	for _, a := range s.sc.Adversaries {
		if a.Node == v.address {
			n.adversary = true
		}
	}
	return n
}

func (n *node) head() uint64 { return index(n.app.chain.head.Header) }

// expectedLive reports whether the node should be running at the end: it
// is alive, or it is down only until a later restart.
func (n *node) expectedLive() bool { return n.alive }

func (n *node) runID() string {
	return fmt.Sprintf("sim-%d-%x-%d", n.s.sc.Seed, n.v.address[:4], n.inc)
}

// faults is the fault-point handler of the node.
func (n *node) faults(name string) {
	for _, f := range n.s.sc.Faults {
		if f.Node != n.v.address || f.Point != name {
			continue
		}
		hit := n.faultHits[name]
		n.faultHits[name] = hit + 1
		if hit == f.Hit {
			panic(crashSignal{point: name})
		}
	}
}

// start starts a new incarnation: open the logs and the signer, run the
// start-up handshake and start the engine.
func (n *node) start() {
	n.inc++
	inc := n.inc
	n.alive, n.down = true, false
	n.clock = &nodeClock{l: &n.s.l, skew: n.spec.ClockSkew, live: func() bool { return n.alive && n.inc == inc }}
	buf := &bytes.Buffer{}
	n.eventFiles["events-"+n.runID()+".jsonl"] = buf
	n.ev = event.NewWriter(buf, n.v.address, n.runID())

	fail := func(err error) {
		n.s.violate("start", n.v.address, "%v", err)
		n.alive, n.down = false, true
	}
	segBytes := n.spec.WALSegmentBytes
	if segBytes <= 0 {
		segBytes = 256 << 10
	}
	log, recov, err := wal.Open(n.fs, walDir, wal.Options{SegmentBytes: segBytes, KeepHeights: 2})
	if err != nil {
		fail(err)
		return
	}
	n.log = log
	if err := n.fs.MkdirAll(privvalDir, 0o700); err != nil {
		fail(err)
		return
	}
	fh := faultpoint.Handler(n.faults)
	signer, err := privval.NewKeySigner(n.fs, fh, n.v.ECDSA, privvalDir+"/state")
	if err != nil {
		// A damaged sign state refuses the start.
		_ = n.ev.Write(event.Record{Kind: event.NodeStart, Fields: map[string]any{"refused": err.Error()}}, n.stamp())
		n.s.violate("start", n.v.address, "sign state: %v", err)
		n.alive, n.down = false, true
		return
	}
	var floor any
	headNum := n.app.chain.head.Header.Number
	if n.spec.TakeoverGuard && signer.Empty() && !headNum.IsZero() {
		if err := signer.InitSignFloor(headNum.AddUint64(1)); err != nil {
			fail(err)
			return
		}
		floor = map[string]any{"height": headNum.AddUint64(1).String(), "status": "set"}
	} else if h, ok := signer.SignFloor(); ok {
		floor = map[string]any{"height": h.String(), "status": "kept"}
	}
	opts := n.spec.Options
	opts.Config, opts.Self = n.s.cfg, n.v.address
	id := journal.Identity{Self: n.v.address, BLSPublicKey: n.v.blsPub, Run: n.runID(), Commit: "sim", ChainID: big.NewInt(ChainID),
		GenesisHash: codec.BlockHash(n.s.genesis.Header), Mode: "standalone",
		Core: journal.CoreOptions{ChainConfig: n.s.cfgJSON, Self: n.v.address, Improvements: uint64(opts.Improvements),
			BacklogLimit: uint64(opts.BacklogLimit), Profile: n.spec.Profile}}
	jw, err := journal.Open(journal.Options{FS: n.fs, Dir: journalDir, KeepHeights: 100000, MaxBytes: 8 << 30,
		SegmentBytes: 1 << 20, Synchronous: true}, id)
	if err != nil {
		fail(err)
		return
	}
	n.jw = jw

	// Start-up handshake.
	st, err := runner.InspectWAL(n.fs, walDir)
	if err != nil {
		fail(err)
		return
	}
	var sh *types.Height
	if h, ok := signer.LastHeight(); ok {
		sh = &h
	}
	act, cr, err := runner.Handshake(n.app.chain.head.Header.Number, st, sh)
	switch act {
	case runner.Refuse:
		fail(err)
		return
	case runner.Refinalize:
		switch err := n.app.importBlock(cr.Block, "sealed_locally"); {
		case errors.Is(err, errImportFail):
			// The decided block fails import again and stays bad.
		case err != nil:
			n.s.violate("refinalize", n.v.address, "%v", err)
		default:
			n.s.refinal++
		}
	}
	n.tr = newAdapter(n)
	dedup, err := transport.NewDedup(n.tr, transport.DedupOptions{Self: n.v.address})
	if err != nil {
		fail(err)
		return
	}
	r, err := runner.New(runner.Config{Core: opts, ReplayWAL: n.spec.ReplayWAL, Manual: true},
		runner.Deps{Chain: n.app, App: n.app, Transport: dedup, Net: n.tr, Signer: recSigner{signer, n}, WAL: log,
			Clock: n.clock, Events: countingSink{n.ev, n.s}, Journal: jw, Rand: n.rng.IntN, Faults: fh})
	if err != nil {
		fail(err)
		return
	}
	n.r, n.signer = r, signer
	_ = n.ev.Write(event.Record{Kind: event.NodeStart, Fields: map[string]any{"impl": "wbft", "mode": "standalone",
		"profile": n.spec.Profile, "sign_floor": floor, "wal_recovery": map[string]any{
			"records": recov.Records, "torn_bytes": recov.TornBytes, "corrupted": len(recov.Corrupted)}}}, n.stamp())
	if !n.guard(func() {
		if err := r.Start(n.s.ctx, n.app.chain.head.Header.Number.AddUint64(1)); err != nil {
			fail(err)
		}
	}) {
		return
	}
	if !n.alive {
		return
	}
	info := r.LastReplay()
	n.s.replays = append(n.s.replays, info)
	if info.Stopped != "" {
		n.s.violate("replay", n.v.address, "%s", info.Stopped)
	}
	if lc := n.pendingLock; lc != nil {
		n.pendingLock = nil
		n.checkLock(lc)
	}
}

// checkLock compares the lock and the prepared certificate after a restart
// with those before the crash, when the node restarted at the same height.
func (n *node) checkLock(lc *lockCheck) {
	if n.head() != lc.head || lc.vars == nil {
		return
	}
	v := n.r.Vars()
	n.s.locks++
	if v == nil {
		n.s.violate("lock_lost", n.v.address, "no state after restart (%s)", lc.point)
		return
	}
	same := func(a, b *types.Round) bool { return a == nil && b == nil || a != nil && b != nil && a.Cmp(*b) == 0 }
	sameH := func(a, b *types.Hash) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
	if !same(v.LockedRound, lc.vars.LockedRound) || !sameH(v.LockedBlock, lc.vars.LockedBlock) || len(v.Certificate) != len(lc.vars.Certificate) {
		n.s.violate("lock_lost", n.v.address, "after %s: lock %v/%v certificate %d, before %v/%v certificate %d", lc.point,
			v.LockedRound, v.LockedBlock, len(v.Certificate), lc.vars.LockedRound, lc.vars.LockedBlock, len(lc.vars.Certificate))
	}
}

func (n *node) stamp() event.Stamp { return event.Stamp{Wall: n.clock.Now(), Mono: n.clock.Mono()} }

// guard runs f and turns a crash signal into a crash of the node. It
// reports whether the node is still alive.
func (n *node) guard(f func()) (alive bool) {
	defer func() {
		if x := recover(); x != nil {
			cs, ok := x.(crashSignal)
			if !ok {
				panic(x)
			}
			n.onFault(cs.point)
			alive = false
		}
	}()
	f()
	return n.alive
}

// onFault crashes the node at a fault point and schedules its restart.
func (n *node) onFault(point string) {
	logged := point == "wal.after_own_msg" || point == "send.before" || point == "send.after" ||
		point == "commit_request.before" || point == "commit_request.after" ||
		point == "end_height.before" || point == "end_height.after"
	if logged && n.r != nil {
		n.pendingLock = &lockCheck{head: n.head(), vars: n.r.Vars(), point: point}
	}
	n.crash()
	for _, f := range n.s.sc.Faults {
		if f.Node == n.v.address && f.Point == point {
			n.s.l.after(f.RestartAfter, func() {
				if !n.alive {
					n.start()
				}
			})
		}
	}
}

// pump drives the node's runner at the current time.
func (n *node) pump() bool {
	if !n.alive || n.r == nil {
		return false
	}
	did := false
	n.guard(func() { did = n.r.Pump() })
	if n.r != nil {
		if h := n.r.Halted(); h != nil && n.alive {
			n.s.violate("halt", n.v.address, "%v", h)
			n.crash()
		}
	}
	return did
}

// stop stops the node cleanly: the engine stops and the logs are closed.
func (n *node) stop() {
	if !n.alive {
		return
	}
	if n.r != nil && n.r.Running() {
		n.guard(func() { _ = n.r.Stop() })
	}
	if n.log != nil {
		_ = n.log.Close()
	}
	if n.jw != nil {
		_ = n.jw.Close()
	}
	n.alive, n.down, n.r = false, true, nil
	n.app.dropPending()
}

// crash kills the node: only synced data survive.
func (n *node) crash() {
	if !n.alive {
		return
	}
	n.s.crashes++
	n.alive, n.down, n.r = false, true, nil
	n.fs.Crash(n.rng)
	n.app.dropPending()
}

// countingSink counts the EVIDENCE events of a node.
type countingSink struct {
	w *event.Writer
	s *simulation
}

func (c countingSink) Write(r event.Record, at event.Stamp) error {
	if r.Kind == event.Evidence {
		c.s.evidence++
	}
	return c.w.Write(r, at)
}

// damage applies a disk fault to a node that is down.
func (n *node) damage(kind string) {
	if n.alive {
		return
	}
	switch kind {
	case DiskTruncateWAL, DiskCorruptWAL:
		segs, err := wal.Segments(n.fs, walDir)
		if err != nil || len(segs) == 0 {
			return
		}
		sg := segs[len(segs)-1]
		if kind == DiskCorruptWAL {
			sg = segs[n.rng.IntN(len(segs))]
		}
		if sg.Size == 0 {
			return
		}
		at := n.rng.Int64N(sg.Size)
		_ = n.fs.Corrupt(walDir+"/"+sg.Name, func(b []byte) []byte {
			if kind == DiskTruncateWAL {
				return b[:at]
			}
			b[at] ^= 0x5a
			return b
		})
		n.s.damaged++
	case DiskPartialSignState:
		if n.fs.Corrupt(privvalDir+"/state", func(b []byte) []byte { return b[:len(b)/2] }) == nil {
			n.s.damaged++
		}
	case DiskLoseState:
		_ = n.fs.Remove(privvalDir + "/state")
		if segs, err := wal.Segments(n.fs, walDir); err == nil {
			for _, sg := range segs {
				_ = n.fs.Remove(walDir + "/" + sg.Name)
			}
		}
		_ = n.fs.SyncDir(privvalDir)
		_ = n.fs.SyncDir(walDir)
		n.s.damaged++
	}
}

// recSigner records every signature for the double-signing check.
type recSigner struct {
	*privval.FileSigner
	n *node
}

func (s recSigner) SignVote(req privval.VoteRequest) (privval.VoteSignature, error) {
	sig, err := s.FileSigner.SignVote(req)
	switch {
	case err == nil:
		s.n.s.noteSigned(s.n, req.Msg)
	case privval.IsRefusal(err) && !s.n.adversary:
		s.n.s.refused++
	}
	return sig, err
}

// signerRandao signs the randao reveal of a block number.
func (n *node) signerRandao(number types.Height) ([]byte, error) {
	return n.signer.SignRandao(big.NewInt(ChainID), number)
}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// eventNewHead is the NEW_HEAD event of a stored block.
func eventNewHead(b *types.Block, path string) event.Record {
	f := map[string]any{"number": b.Header.Number.String(), "hash": "0x" + hex.EncodeToString(codec.BlockHash(b.Header).Bytes()), "path": path}
	if x, err := codec.DecodeExtra(b.Header); err == nil {
		f["round"] = fmt.Sprint(x.Round)
		if x.PreparedSeal != nil {
			f["prepared_sealers"] = x.PreparedSeal.Sealers.Sealers()
		}
		if x.CommittedSeal != nil {
			f["committed_sealers"] = x.CommittedSeal.Sealers.Sealers()
		}
	}
	return event.Record{Kind: event.NewHead, Fields: f}
}
