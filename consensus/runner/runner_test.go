package runner

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// reachPrepared takes node 1 to Prepared on a at (10, 0).
func reachPrepared(t *testing.T, n *tnode, a *types.Block) {
	t.Helper()
	k := n.k
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))
	n.deliver(0, codec.CodePrepare, k.vote(t, 0, codec.CodePrepare, view(10, 0), a))
	n.deliver(2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), a))
	if v := n.r.Vars(); v.State != consensus.Prepared {
		t.Fatalf("state %s", v.State)
	}
	if len(n.net.own(codec.CodeCommit)) != 1 {
		t.Fatal("no COMMIT sent")
	}
}

// After a crash the replay restores the lock, the certificate and the
// state, re-arms the round timer and sends the last own COMMIT again with
// the same bytes.
func TestReplayRestoresLock(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	before := n.r.Vars()
	commit := n.net.own(codec.CodeCommit)[0]
	n.crash()
	n.net.sent = nil
	n.boot()
	info := n.r.LastReplay()
	if !info.Replayed || info.Stopped != "" || info.Records == 0 {
		t.Fatalf("replay %+v", info)
	}
	after := n.r.Vars()
	if after.State != consensus.Prepared || after.LockedRound == nil || after.LockedRound.Cmp(*before.LockedRound) != 0 ||
		*after.LockedBlock != *before.LockedBlock || len(after.Certificate) != len(before.Certificate) {
		t.Fatalf("after replay %+v, before %+v", after, before)
	}
	resent := n.net.own(codec.CodeCommit)
	if len(resent) != 1 || !bytes.Equal(resent[0], commit) {
		t.Fatalf("COMMIT not re-sent with the same bytes: %d", len(resent))
	}
	// The round timer runs again; its expiry sends a ROUND-CHANGE that
	// reports the lock, which the sign rules allow.
	n.advance(2 * time.Second)
	rcs := n.net.own(codec.CodeRoundChange)
	if len(rcs) != 1 {
		t.Fatalf("ROUND-CHANGEs %d", len(rcs))
	}
	m, _ := codec.DecodeMessage(codec.CodeRoundChange, rcs[0])
	if m.PreparedRound == nil || m.PreparedDigest != codec.BlockHash(a.Header) {
		t.Fatal("ROUND-CHANGE without the lock")
	}
	if len(n.events.kinds(event.Health)) != 0 {
		t.Fatalf("health events %v", n.events.kinds(event.Health))
	}
}

// Without the replay the restarted core has no lock: its lock-less
// ROUND-CHANGE is refused by privval (it signed a COMMIT of round 0) and
// reported to the core as a failed broadcast.
func TestWithoutReplayPrivvalRefuses(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	n.crash()
	n.net.sent = nil
	// Boot without replay.
	n.opts.Improvements = consensus.RestartSafety
	bootNoReplay(t, n)
	if n.r.Vars().LockedRound != nil {
		t.Fatal("lock without replay")
	}
	n.advance(2 * time.Second)
	if len(n.net.own(codec.CodeRoundChange)) != 0 {
		t.Fatal("lock-less ROUND-CHANGE sent")
	}
	h := n.events.kinds(event.Health)
	if len(h) == 0 || h[0].Fields["what"] != "privval_refusal" {
		t.Fatalf("health %v", h)
	}
}

func bootNoReplay(t *testing.T, n *tnode) {
	n.boot()
	// Rebuild the runner without replay on the same logs.
	n.r = nil
	log := n.log
	_ = log.Close()
	l2, _, err := walOpen(n)
	if err != nil {
		t.Fatal(err)
	}
	dd, _ := transport.NewDedup(n.net, transport.DedupOptions{Self: n.k.addrs[n.self]})
	n.events = &eventLog{}
	r, err := New(Config{Core: n.opts, Manual: true}, Deps{Chain: n.chain, App: n.app, Transport: dd, Net: n.net,
		Signer: n.signer, WAL: l2, Clock: n.clock, Events: n.events})
	if err != nil {
		t.Fatal(err)
	}
	n.r = r
	if err := r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	r.Pump()
}

// A signature below the sign floor is refused and reported to the core;
// the node emits one sign_floor_skip per height and keeps receiving.
func TestSignFloorSkip(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	if err := n.fs.MkdirAll("/pv", 0o700); err != nil {
		t.Fatal(err)
	}
	n.boot()
	if err := n.signer.InitSignFloor(types.HeightFromUint64(10)); !errors.Is(err, nil) {
		t.Fatal(err)
	}
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))
	if len(n.net.own(codec.CodePrepare)) != 0 {
		t.Fatal("signed below the floor")
	}
	h := n.events.kinds(event.Health)
	if len(h) != 1 || h[0].Fields["what"] != "sign_floor_skip" {
		t.Fatalf("health %v", h)
	}
	if v := n.r.Vars(); v.State != consensus.Preprepared {
		t.Fatalf("state %s", v.State)
	}
}

func TestHandshake(t *testing.T) {
	k := newKeys(t, 1)
	b := block(t, 11, 0, k.addrs[0], types.Hash{})
	h10, h11, h12 := types.HeightFromUint64(10), types.HeightFromUint64(11), types.HeightFromUint64(12)
	cases := []struct {
		name string
		st   WALState
		sign *types.Height
		want HandshakeAction
	}{
		{"empty", WALState{}, nil, StartNormal},
		{"normal", WALState{LastEnd: &h10}, &h11, StartNormal},
		{"commit request", WALState{LastEnd: &h10, Commits: []CommitRequest{{Block: b}}}, &h11, Refinalize},
		{"app rollback", WALState{LastEnd: &h11}, nil, StartAfterRollback},
		{"log ahead", WALState{LastEnd: &h12}, nil, Refuse},
		{"sign ahead", WALState{}, &h12, Refuse},
	}
	for _, c := range cases {
		got, cr, err := Handshake(h10, c.st, c.sign)
		if got != c.want || (got == Refinalize) != (cr != nil) || (got == Refuse) != (err != nil) {
			t.Errorf("%s: %v %v %v", c.name, got, cr, err)
		}
	}
}

// The start-up handshake finds the commit request of a block the node
// decided before a crash.
func TestInspectWALCommitRequest(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	n.deliver(0, codec.CodeCommit, k.vote(t, 0, codec.CodeCommit, view(10, 0), a))
	n.deliver(2, codec.CodeCommit, k.vote(t, 2, codec.CodeCommit, view(10, 0), a))
	n.crash()
	st, err := InspectWAL(n.fs, "/wal")
	if err != nil {
		t.Fatal(err)
	}
	act, cr, err := Handshake(n.chain.head.Number, st, nil)
	if err != nil || act != Refinalize || codec.BlockHash(cr.Block.Header) != codec.BlockHash(a.Header) {
		t.Fatalf("%v %v %v", act, cr, err)
	}
}

func TestReceiveChecks(t *testing.T) {
	k := newKeys(t, 5)
	n := newTNode(t, k, 1)
	// Validator 4 is not in the set.
	n.chain.vs = newKeys(t, 4).vs
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	outcome := func() map[string]any {
		o := n.events.kinds(event.MsgOutcome)
		return o[len(o)-1].Fields
	}
	// Bad signature.
	bad := k.vote(t, 0, codec.CodePrepare, view(10, 0), a)
	bad[len(bad)-2] ^= 1
	n.deliver(0, codec.CodePrepare, bad)
	if f := outcome(); f["check"] != "prefilter" || f["reason"] != "signature" && f["reason"] != "membership" {
		t.Fatalf("bad signature: %v", f)
	}
	// Not a member.
	n.deliver(4, codec.CodePrepare, k.vote(t, 4, codec.CodePrepare, view(10, 0), a))
	if f := outcome(); f["reason"] != "membership" {
		t.Fatalf("membership: %v", f)
	}
	// Too far.
	n.deliver(0, codec.CodePrepare, k.vote(t, 0, codec.CodePrepare, view(10, 50), a))
	if f := outcome(); f["reason"] != "window" {
		t.Fatalf("window: %v", f)
	}
	// A duplicate from another peer is dropped by the known cache.
	p := k.vote(t, 2, codec.CodeCommit, view(10, 0), a)
	n.deliver(2, codec.CodeCommit, p)
	n.deliver(3, codec.CodeCommit, p)
	if f := outcome(); f["reason"] != "duplicate" || f["outcome"] != event.DropSilent {
		t.Fatalf("duplicate: %v", f)
	}
}

// A second PREPARE of one source for one view overwrites the first in its
// slot before the core takes it, and the receive check reports EVIDENCE.
func TestSlotOverwriteEvidence(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	b := block(t, 10, 2, k.addrs[0], codec.BlockHash(n.chain.head))
	r := n.r.Receiver()
	r.Offer(transportInbound(k, 2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), a), 0))
	r.Offer(transportInbound(k, 3, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), b), 0))
	n.r.Pump()
	ev := n.events.kinds(event.Evidence)
	if len(ev) != 1 || ev[0].Fields["kind"] != "equivocation" {
		t.Fatalf("evidence %v", ev)
	}
	// Two round-0 PRE-PREPAREs of the proposer both reach the core, the
	// first first.
	n2 := newTNode(t, k, 1)
	n2.boot()
	r2 := n2.r.Receiver()
	r2.Offer(transportInbound(k, 0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a), 0))
	r2.Offer(transportInbound(k, 3, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b), 0))
	n2.r.Pump()
	var checks []any
	for _, o := range n2.events.kinds(event.MsgOutcome) {
		checks = append(checks, o.Fields["check"])
	}
	prep := n2.net.own(codec.CodePrepare)
	if len(prep) != 1 {
		t.Fatalf("PREPAREs %d, outcomes %v", len(prep), checks)
	}
	m, _ := codec.DecodeMessage(codec.CodePrepare, prep[0])
	if m.Digest != codec.BlockHash(a.Header) {
		t.Fatal("the second PRE-PREPARE was taken first")
	}
}

func TestStoppedEngine(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	n.r.Receiver().Offer(transportInbound(k, 0, codec.CodePrepare, []byte{0xc0}, 0))
	if len(n.net.discon) != 1 {
		t.Fatal("no disconnect while stopped and not synchronising")
	}
	n.r.d.Synchronising = func() bool { return true }
	n.r.Receiver().Offer(transportInbound(k, 0, codec.CodePrepare, []byte{0xc0}, 0))
	if len(n.net.discon) != 1 {
		t.Fatal("disconnect while synchronising")
	}
	// A restart of the engine in the same process replays the log.
	if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	if !n.r.Running() || n.r.EngineRun() != 2 {
		t.Fatal("engine not restarted")
	}
}

func TestInboxOverflow(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	n.r.cfg.InboxMessages = 3
	n.r.cfg.OverflowLimit = 5
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	r := n.r.Receiver()
	accepted := 0
	for i := 0; i < 20; i++ {
		v := k.vote(t, 0, codec.CodePrepare, view(10, uint64(i%9)), a)
		if r.Offer(transportInbound(k, 0, codec.CodePrepare, v, 0)) {
			accepted++
		}
	}
	if accepted != 3 || len(n.net.discon) == 0 || n.net.discon[0] != k.addrs[0] {
		t.Fatalf("accepted %d, disconnected %v", accepted, n.net.discon)
	}
	h := n.events.kinds(event.Health)
	if len(h) < 2 || h[0].Fields["what"] != "peer_inbound_overflow" {
		t.Fatalf("health %v", h)
	}
}

// The journal step records replay to the same output digests.
func TestJournalSteps(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	recs, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	core := consensus.NewState(n.opts)
	env := &replayEnv{head: n.chain.head}
	steps := 0
	for _, rec := range recs {
		s, ok := rec.Body.(*journal.StepRec)
		if !ok {
			continue
		}
		in, err := inputlog.Decode(s.InputKind, s.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		senv := &startEnv{head: n.chain.head, vs: k.vs}
		var outs []consensus.Output
		if s.InputKind == inputlog.KindStart {
			outs = core.Step(senv, in)
		} else {
			env.answers, env.err = nil, nil
			for _, b := range s.Env {
				c, _ := inputlog.DecodeEnv(b)
				env.answers = append(env.answers, c)
			}
			outs = core.Step(env, in)
		}
		d, _ := inputlog.OutDigest(outs)
		if d != s.OutDigest {
			t.Fatalf("step %d (%s): digest differs", s.Step, s.InputKind)
		}
		steps++
	}
	if steps < 5 {
		t.Fatalf("%d steps", steps)
	}
}

// gnode is a runner with goroutines, its chain and its application.
type gnode struct {
	r     *Runner
	chain *fakeChain
	i     int
	k     *keys
	t     *testing.T
	mu    *sync.Mutex
	dec   map[uint64]types.Hash
}

// ReadyToBuild builds a block on the head after the wait and submits it.
func (g *gnode) ReadyToBuild(req consensus.RequestBuild, wait time.Duration, done <-chan struct{}) {
	go func() {
		select {
		case <-time.After(wait):
		case <-done:
			return
		}
		head := g.chain.Head()
		if head.Number.AddUint64(1).Cmp(req.Height) != 0 {
			return
		}
		g.r.Submit(block(g.t, head.Number.Big().Uint64()+1, byte(g.i), g.k.addrs[g.i], codec.BlockHash(head)))
	}()
}

// FinalizeBlock stores the block as the head and reports the new head.
func (g *gnode) FinalizeBlock(b *types.Block, _ types.Round) error {
	g.mu.Lock()
	n := b.Header.Number.Big().Uint64()
	if old, ok := g.dec[n]; ok && old != codec.BlockHash(b.Header) {
		g.t.Errorf("disagreement at %d", n)
	}
	g.dec[n] = codec.BlockHash(b.Header)
	g.mu.Unlock()
	g.chain.mu.Lock()
	if b.Header.Number.Cmp(g.chain.head.Number.AddUint64(1)) == 0 {
		g.chain.head = b.Header
	}
	g.chain.mu.Unlock()
	g.r.NewHead(b.Header)
	return nil
}

// router delivers sends between runners in memory.
type router struct {
	mu sync.Mutex
	rs map[types.Address]*Runner
}

func (rt *router) add(a types.Address, r *Runner) {
	rt.mu.Lock()
	if rt.rs == nil {
		rt.rs = map[types.Address]*Runner{}
	}
	rt.rs[a] = r
	rt.mu.Unlock()
}

type routeNet struct {
	rt   *router
	self types.Address
	all  []types.Address
}

func (n *routeNet) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	for _, p := range peers {
		n.rt.mu.Lock()
		r := n.rt.rs[p]
		n.rt.mu.Unlock()
		if r != nil {
			r.Receiver().Offer(transport.Inbound{Peer: n.self, Code: code, Payload: payload})
		}
	}
	return make([]transport.SendResult, len(peers))
}
func (n *routeNet) SetReceiver(transport.Receiver)         {}
func (n *routeNet) PeerEvents() <-chan transport.PeerEvent { return nil }
func (n *routeNet) Disconnect(types.Address, string)       {}
func (n *routeNet) Peers() []transport.PeerInfo {
	var out []transport.PeerInfo
	for _, a := range n.all {
		if a != n.self {
			out = append(out, transport.PeerInfo{Addr: a})
		}
	}
	return out
}

// With goroutines and the system clock four runners decide heights.
func TestGoroutineRunners(t *testing.T) {
	k := newKeys(t, 4)
	var mu sync.Mutex
	dec := map[uint64]types.Hash{}
	clock := SystemClock()
	rt := &router{}
	var nodes []*gnode
	for i := 0; i < 4; i++ {
		pol := uint64(0)
		cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)
		g := &gnode{chain: &fakeChain{head: block(t, 9, 0, k.addrs[3], types.Hash{}).Header, vs: k.vs, clock: clock,
			future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}, i: i, k: k, t: t, mu: &mu, dec: dec}
		dd, _ := transport.NewDedup(&routeNet{rt: rt, self: k.addrs[i], all: k.addrs}, transport.DedupOptions{Self: k.addrs[i]})
		r, err := New(Config{Core: consensus.Options{Config: cfg, Self: k.addrs[i], Improvements: consensus.RestartSafety}, Workers: 2},
			Deps{Chain: g.chain, App: g, Transport: dd, Signer: mustSigner(t, k, i), Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		g.r = r
		rt.add(k.addrs[i], r)
		nodes = append(nodes, g)
	}
	for _, g := range nodes {
		if err := g.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		done := true
		for _, g := range nodes {
			if g.chain.Head().Number.CmpUint64(13) < 0 {
				done = false
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no progress")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, g := range nodes {
		if err := g.r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func mustSigner(t *testing.T, k *keys, i int) *privval.FileSigner {
	fs := fsys.NewMem()
	_ = fs.MkdirAll("/pv", 0o700)
	s, err := privval.NewKeySigner(fs, nil, k.secret[i], "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func walOpen(n *tnode) (*wal.Log, wal.Recovery, error) { return wal.Open(n.fs, "/wal", wal.Options{}) }

// When every peer's queue overflows the node itself is slow: nobody is
// disconnected.
func TestInboxAllOverflowNoDisconnect(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	n.r.cfg.InboxMessages = 2
	n.r.cfg.OverflowLimit = 3
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	r := n.r.Receiver()
	for i := 0; i < 12; i++ {
		for _, p := range []int{0, 2, 3} {
			v := k.vote(t, p, codec.CodePrepare, view(10, uint64(i%9)), a)
			r.Offer(transportInbound(k, p, codec.CodePrepare, v, 0))
		}
	}
	if len(n.net.discon) != 0 {
		t.Fatalf("disconnected %v", n.net.discon)
	}
}

// An application head that moved without a notification is noticed by the
// periodic head check, reported and handed to the core.
func TestHeadCheck(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.chain.mu.Lock()
	n.chain.head = b.Header
	n.chain.mu.Unlock()
	n.advance(HeadCheckPeriod)
	h := n.events.kinds(event.Health)
	if len(h) == 0 || h[0].Fields["what"] != "head_mismatch" {
		t.Fatalf("health %v", h)
	}
	if v := n.r.Vars(); v.View.Sequence.CmpUint64(11) != 0 {
		t.Fatalf("core at %s", v.View.Sequence)
	}
}
