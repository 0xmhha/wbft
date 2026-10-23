package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// These tests drive the actual receiver, core actor and WAL with a local chain
// adapter. They are not a governance-contract or live-network acceptance test.
type nextHeightNode struct {
	t      *testing.T
	k      *keys
	fs     *fsys.Mem
	chain  *fakeChain
	clock  *manualClock
	r      *Runner
	log    *wal.Log
	jw     journal.Writer
	events *eventLog
	limits *NextHeightLimits
	opts   consensus.Options
}

func nextHeightSet(t testing.TB, k *keys, indices []int) *validator.Set {
	t.Helper()
	var addrs []types.Address
	var pubs [][]byte
	for _, i := range indices {
		addrs = append(addrs, k.addrs[i])
		pubs = append(pubs, k.bls[i].PublicKey().Bytes())
	}
	vs, err := validator.NewSet(addrs, pubs, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func newNextHeightNode(t *testing.T, k *keys, vs *validator.Set, h types.Height, limits *NextHeightLimits, recording bool) *nextHeightNode {
	t.Helper()
	clock := &manualClock{}
	n := &nextHeightNode{t: t, k: k, fs: fsys.NewMem(), clock: clock, limits: limits}
	head := block(t, 1, 0, vs.At(vs.Len()-1).Addr, types.Hash{}).Header
	head.Number, _ = h.Sub(types.HeightFromUint64(1))
	n.chain = &fakeChain{head: head, vs: vs, clock: clock, future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}
	pol := uint64(0)
	n.opts = consensus.Options{Config: types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)}
	if recording {
		jw, err := journal.Open(journal.Options{FS: fsys.NewMem(), Dir: "/j", Synchronous: true}, journal.Identity{Run: "first-writer"})
		if err != nil {
			t.Fatal(err)
		}
		n.jw = jw
	}
	n.boot()
	t.Cleanup(func() {
		n.close()
		if n.jw != nil {
			_ = n.jw.Close()
		}
	})
	return n
}

func (n *nextHeightNode) boot() {
	n.t.Helper()
	log, _, err := wal.Open(n.fs, "/wal", wal.Options{SegmentBytes: 2048, KeepHeights: 1})
	if err != nil {
		n.t.Fatal(err)
	}
	n.log, n.events = log, &eventLog{}
	n.r, err = New(Config{Core: n.opts, ReplayWAL: true, Manual: true, NextHeight: n.limits}, Deps{Chain: n.chain, App: &fakeApp{}, Clock: n.clock, WAL: log, Journal: n.jw, Events: n.events, Rand: func(int) int { return 0 }})
	if err != nil {
		n.t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.Head().Number.AddUint64(1)); err != nil {
		n.t.Fatal(err)
	}
}

func (n *nextHeightNode) close() {
	if n.r != nil {
		if err := n.r.Close(); err != nil {
			n.t.Fatal(err)
		}
		n.r = nil
	}
	if n.log != nil {
		if err := n.log.Close(); err != nil {
			n.t.Fatal(err)
		}
		n.log = nil
	}
}

func (n *nextHeightNode) advance(head *types.Header, vs *validator.Set, pump bool) {
	n.chain.mu.Lock()
	n.chain.head, n.chain.vs = head, vs
	n.chain.mu.Unlock()
	n.r.NewHead(head)
	if pump {
		n.r.Pump()
	} else if !n.r.processOne() {
		n.t.Fatal("new-head input was not processed")
	}
}

func nextHeightMessages(t *testing.T, k *keys, h types.Height, b *types.Block, members []int, outer int) []*codec.Message {
	t.Helper()
	signed := func(i int, m *codec.Message, seal []byte) *codec.Message {
		p := k.sign(t, i, m, seal)
		d, err := codec.DecodeMessage(m.Code, p)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	v := func(r uint64) types.View { return types.View{Sequence: h, Round: types.RoundFromUint64(r)} }
	pr := types.RoundFromUint64(1)
	digest := codec.BlockHash(b.Header)
	var ps, rcs []*codec.Message
	for _, i := range members[:2*len(members)/3+1] {
		ps = append(ps, signed(i, &codec.Message{Code: codec.CodePrepare, View: v(1), Digest: digest}, codec.SealData(b.Header, 1, types.PrepareSeal)))
		rcs = append(rcs, signed(i, &codec.Message{Code: codec.CodeRoundChange, View: v(2), PreparedRound: &pr, PreparedDigest: digest}, nil))
	}
	return []*codec.Message{
		signed(outer, &codec.Message{Code: codec.CodePrepare, View: v(0), Digest: digest}, codec.SealData(b.Header, 0, types.PrepareSeal)),
		signed(outer, &codec.Message{Code: codec.CodeCommit, View: v(0), Digest: digest}, codec.SealData(b.Header, 0, types.CommitSeal)),
		signed(outer, &codec.Message{Code: codec.CodeRoundChange, View: v(1)}, nil),
		signed(outer, &codec.Message{Code: codec.CodeRoundChange, View: v(2), PreparedRound: &pr, PreparedDigest: digest, PreparedBlock: b, Prepares: ps}, nil),
		signed(outer, &codec.Message{Code: codec.CodePreprepare, View: v(0), Proposal: b}, nil),
		signed(outer, &codec.Message{Code: codec.CodePreprepare, View: v(2), Proposal: b, RoundChanges: rcs, Prepares: ps}, nil),
	}
}

func TestNextHeightReceiverRotationAndRestart(t *testing.T) {
	for _, size := range []int{4, 7, 21} {
		k := newKeys(t, size+1)
		old := make([]int, size)
		for i := range old {
			old[i] = i
		}
		joined := append(slices.Clone(old[1:]), size)
		oldSet, newSet := nextHeightSet(t, k, old), nextHeightSet(t, k, joined)
		for _, bits := range []uint{0, 64, 128} {
			bign := big.NewInt(10)
			if bits != 0 {
				bign.Add(bign, new(big.Int).Lsh(big.NewInt(1), bits))
			}
			h := types.MustHeightFromBig(bign)
			states := map[string]*consensus.Vars{}
			for _, recording := range []bool{false, true} {
				for _, roster := range []string{"joined", "departed_outer", "departed_nested"} {
					t.Run(fmt.Sprintf("n%d/h%s/record%t/%s", size, h.String(), recording, roster), func(t *testing.T) {
						limits := &NextHeightLimits{Entries: 12, Bytes: 1 << 20, PerPeer: 12, PerSource: 12}
						n := newNextHeightNode(t, k, oldSet, h, limits, recording)
						head := block(t, 10, 1, k.addrs[size-1], codec.BlockHash(n.chain.Head())).Header
						head.Number = h
						b := block(t, 11, 2, k.addrs[size], codec.BlockHash(head))
						b.Header.Number = h.AddUint64(1)
						members, outer := joined, size
						if roster == "departed_outer" {
							members, outer = old, 0
						}
						if roster == "departed_nested" {
							members, outer = old, 1
						}
						messages := nextHeightMessages(t, k, h.AddUint64(1), b, members, outer)
						var originals [][]byte
						for i, m := range messages {
							raw, err := codec.EncodeMessage(m)
							if err != nil {
								t.Fatal(err)
							}
							originals = append(originals, bytes.Clone(raw))
							before := sha256.Sum256(raw)
							in := transport.Inbound{Code: uint64(m.Code), Payload: raw, Peer: k.addrs[1], RecvMono: time.Duration(i + 1), Capture: uint64(i + 10)}
							if !n.r.Receiver().Offer(in) {
								t.Fatal("normal next-height offer refused")
							}
							if e, b := n.r.NextHeightUsage(); e != uint64(i+1) || b == 0 {
								t.Fatal("reservation not retained at offer")
							}
							n.r.Pump()
							if sha256.Sum256(raw) != before {
								t.Fatal("receiver mutated input")
							}
						}
						if len(n.events.kinds(event.MsgOutcome)) != 0 || len(n.events.kinds(event.Evidence)) != 0 || n.r.Snapshot().Backlog != 0 {
							t.Fatal("outer-only frame reached core or evidence")
						}
						assertNextHeightPending(t, n, originals, recording)
						// A normal process close/open before changing height restores
						// admissions even when there were no core message steps.
						n.close()
						if recording {
							if err := n.jw.Close(); err != nil {
								t.Fatal(err)
							}
							jw, err := journal.Open(journal.Options{FS: fsys.NewMem(), Dir: "/new-journal", Synchronous: true}, journal.Identity{Run: "second-writer"})
							if err != nil {
								t.Fatal(err)
							}
							n.jw = jw
						}
						n.boot()
						assertNextHeightPending(t, n, originals, recording)
						// Persist the real runner height boundary without dispatching
						// pending messages, then close/open across that boundary.
						n.advance(head, newSet, false)
						assertNextHeightPending(t, n, originals, recording)
						n.close()
						n.boot()
						assertNextHeightPending(t, n, originals, recording)
						n.r.Pump()
						if err := n.r.Halted(); err != nil {
							t.Fatal(err)
						}
						if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
							t.Fatalf("unreleased reservations %d/%d", e, b)
						}
						outcomes := n.events.kinds(event.MsgOutcome)
						if len(outcomes) != len(messages) {
							t.Fatalf("outcomes %d, want %d", len(outcomes), len(messages))
						}
						for i, rec := range outcomes {
							row := rec.Fields["row"].(int)
							wantUnauthorized := roster == "departed_outer" || roster == "departed_nested" && (i == 3 || i == 5)
							if (row == 2) != wantUnauthorized {
								t.Fatalf("message %d row %d, unauthorized %t", i, row, wantUnauthorized)
							}
						}
						// Completed release inputs replay through the same core path.
						before := n.r.Vars()
						if recording {
							if !reflect.DeepEqual(before, states[roster]) {
								t.Fatal("recorder changed functional Vars")
							}
						} else {
							states[roster] = before
						}
						n.close()
						n.boot()
						if !n.r.LastReplay().Replayed || n.r.LastReplay().Stopped != "" || n.r.LastReplay().Records < len(messages) {
							t.Fatalf("replay %+v", n.r.LastReplay())
						}
						after := n.r.Vars()
						if !reflect.DeepEqual(before, after) {
							t.Fatal("release replay changed core state")
						}
						if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
							t.Fatal("replayed release was admitted again")
						}
						st, err := InspectWAL(n.fs, "/wal")
						if err != nil || st.LastEnd == nil || st.LastEnd.Cmp(h) != 0 {
							t.Fatalf("handshake boundary missing: %+v %v", st, err)
						}
					})
				}
			}
		}
	}
}

func assertNextHeightPending(t *testing.T, n *nextHeightNode, originals [][]byte, recording bool) {
	t.Helper()
	p := n.r.nextHeight
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) != len(originals) {
		t.Fatalf("pending %d, want %d", len(p.order), len(originals))
	}
	var total uint64
	for i, id := range p.order {
		e := p.entries[id]
		if e.stage != deferredPending || !bytes.Equal(e.record.Payload, originals[i]) || e.record.Peer != n.k.addrs[1] || e.record.RecvMono != uint64(i+1) {
			t.Fatalf("pending %d lost its bytes, metadata or ownership", i)
		}
		if recording && (e.record.CaptureRun != "first-writer" || e.record.Capture != uint64(i+10)) {
			t.Fatal("original writer/capture reference changed")
		}
		if !recording && (e.record.CaptureRun != "" || e.record.Capture != 0) {
			t.Fatal("invented physical reference without a recorder")
		}
		total += uint64(len(originals[i]))
	}
	if p.bytes != total {
		t.Fatalf("reserved %d, want %d", p.bytes, total)
	}
}

func TestNextHeightBudgetAndCurrentProgress(t *testing.T) {
	k := newKeys(t, 5)
	vs := nextHeightSet(t, k, []int{0, 1, 2, 3})
	b := block(t, 11, 1, k.addrs[4], types.Hash{})
	first := k.vote(t, 4, codec.CodePrepare, view(11, 0), b)
	second := k.vote(t, 4, codec.CodeCommit, view(11, 0), b)
	for _, limit := range []string{"entries", "bytes", "peer", "source", "first_slot"} {
		t.Run(limit, func(t *testing.T) {
			l := &NextHeightLimits{Entries: 2, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}
			switch limit {
			case "entries":
				l.Entries = 1
			case "bytes":
				l.Bytes = uint64(len(first))
			case "peer":
				l.PerPeer = 1
			case "source":
				l.PerSource = 1
			}
			n := newNextHeightNode(t, k, vs, types.HeightFromUint64(10), l, false)
			if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: first, Peer: k.addrs[1]}) {
				t.Fatal("first ordinary message refused")
			}
			p := n.r.nextHeight
			p.mu.Lock()
			if &p.entries[p.order[0]].record.Payload[0] == &first[0] {
				t.Fatal("future lane retained caller storage")
			}
			p.mu.Unlock()
			code, raw := codec.CodeCommit, second
			if limit == "first_slot" {
				code, raw = codec.CodePrepare, first
			}
			accepted := n.r.Receiver().Offer(transport.Inbound{Code: uint64(code), Payload: raw, Peer: k.addrs[1]})
			if accepted != (limit == "source" || limit == "first_slot") {
				t.Fatal("wrong pre-authentication admission limit")
			}
			n.r.Pump()
			if e, b := n.r.NextHeightUsage(); e != 1 || b != uint64(len(first)) {
				t.Fatalf("budget after outer authentication %d/%d", e, b)
			}
			// The ordinary current-height path has independent queue capacity.
			current := k.vote(t, 0, codec.CodePrepare, view(10, 0), b)
			if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: current, Peer: k.addrs[1]}) {
				t.Fatal("future reservation consumed current queue capacity")
			}
			n.r.Pump()
			if len(n.events.kinds(event.MsgOutcome)) != 1 {
				t.Fatal("current-height input did not progress")
			}
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
				t.Fatal("Stop retained receive workspace")
			}
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
				t.Fatal(err)
			}
			if e, b := n.r.NextHeightUsage(); e != 1 || b != uint64(len(first)) {
				t.Fatal("Stop/Start lost durable admission")
			}
		})
	}
}

func TestNextHeightNormalSyncWhileStopped(t *testing.T) {
	for _, skip := range []uint64{1, 2} {
		t.Run(fmt.Sprintf("advance%d", skip), func(t *testing.T) {
			k := newKeys(t, 5)
			old := nextHeightSet(t, k, []int{0, 1, 2, 3})
			joined := nextHeightSet(t, k, []int{1, 2, 3, 4})
			n := newNextHeightNode(t, k, old, types.HeightFromUint64(10), &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}, false)
			b := block(t, 11, 1, k.addrs[4], types.Hash{})
			raw := k.vote(t, 4, codec.CodePrepare, view(11, 0), b)
			if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: raw, Peer: k.addrs[1]}) {
				t.Fatal("offer")
			}
			n.r.Pump()
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			n.chain.head = block(t, 9+skip, 2, k.addrs[3], codec.BlockHash(n.chain.head)).Header
			n.chain.vs = joined
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10+skip)); err != nil {
				t.Fatal(err)
			}
			if e, _ := n.r.NextHeightUsage(); e != 1 {
				t.Fatal("sync start lost pending checkpoint")
			}
			n.r.Pump()
			if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
				t.Fatal("sync did not consume or expire admission")
			}
			if got := len(n.events.kinds(event.MsgOutcome)); got != int(2-skip) {
				t.Fatalf("sync core inputs %d", got)
			}
			n.close()
			n.boot()
			n.r.Pump()
			if e, _ := n.r.NextHeightUsage(); e != 0 {
				t.Fatal("sync replay resurrected completed entry")
			}
		})
	}
}

func TestNextHeightDefaultAndWALProfile(t *testing.T) {
	k := newKeys(t, 5)
	old := nextHeightSet(t, k, []int{0, 1, 2, 3})
	n := newNextHeightNode(t, k, old, types.HeightFromUint64(10), nil, false)
	b := block(t, 11, 1, k.addrs[4], types.Hash{})
	n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: k.vote(t, 4, codec.CodePrepare, view(11, 0), b), Peer: k.addrs[1]})
	n.r.Pump()
	out := n.events.kinds(event.MsgOutcome)
	if len(out) != 1 || out[0].Fields["reason"] != "membership" {
		t.Fatal("default receiver behavior changed")
	}
	if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
		t.Fatal("default retained a deferred frame")
	}
	if records, _, err := wal.ReadAll(n.fs, "/wal"); err != nil {
		t.Fatal(err)
	} else {
		for _, rec := range records {
			if rec.Format != walFormat {
				t.Fatal("default WAL bytes changed")
			}
		}
	}
	n.close()
	// Open an ordinary, valid opt-in WAL with replay disabled or without the
	// opt-in receive configuration: both configurations must refuse it explicitly.
	n.limits = &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}
	n.boot()
	n.close()
	for _, replay := range []bool{false, true} {
		log, _, err := wal.Open(n.fs, "/wal", wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		r, err := New(Config{Core: n.opts, ReplayWAL: replay, Manual: true}, Deps{Chain: n.chain, App: &fakeApp{}, Clock: n.clock, WAL: log})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Start(context.Background(), types.HeightFromUint64(10)); err == nil {
			t.Fatal("opt-in WAL silently downgraded")
		}
		_ = r.Close()
		_ = log.Close()
	}
}

type lockedNextHeightChain struct{ *fakeChain }

func (c lockedNextHeightChain) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vs, nil
}

type reservationObserver struct {
	log  eventLog
	mu   sync.Mutex
	r    *Runner
	held bool
}

func (o *reservationObserver) Write(rec event.Record, stamp event.Stamp) error {
	if rec.Kind == event.MsgOutcome && rec.View != nil && rec.View.Seq == "11" {
		if e, b := o.r.NextHeightUsage(); e == 1 && b > 0 {
			o.mu.Lock()
			o.held = true
			o.mu.Unlock()
		}
	}
	return o.log.Write(rec, stamp)
}

func TestNextHeightThreadedWorkerAndConsumption(t *testing.T) {
	k := newKeys(t, 5)
	old := nextHeightSet(t, k, []int{0, 1, 2, 3})
	joined := nextHeightSet(t, k, []int{1, 2, 3, 4})
	head := block(t, 9, 0, k.addrs[3], types.Hash{}).Header
	clock := SystemClock()
	chain := &fakeChain{head: head, vs: old, clock: clock, future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}
	log, _, err := wal.Open(fsys.NewMem(), "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pol := uint64(0)
	opts := consensus.Options{Config: types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 20, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)}
	observer := &reservationObserver{}
	r, err := New(Config{Core: opts, ReplayWAL: true, Workers: 1, NextHeight: &NextHeightLimits{Entries: 1, Bytes: 1 << 20, PerPeer: 1, PerSource: 1}}, Deps{Chain: lockedNextHeightChain{chain}, App: &fakeApp{}, Clock: clock, WAL: log, Events: observer})
	if err != nil {
		t.Fatal(err)
	}
	observer.r = r
	t.Cleanup(func() { _ = r.Close(); _ = log.Close() })
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	wait := func(ready func() bool) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for !ready() {
			select {
			case <-deadline.C:
				t.Fatal("ordinary runner progress timed out")
			case <-tick.C:
			}
		}
	}
	b := block(t, 11, 1, k.addrs[4], types.Hash{})
	future := k.vote(t, 4, codec.CodePrepare, view(11, 0), b)
	if !r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: future, Peer: k.addrs[1]}) {
		t.Fatal("future offer")
	}
	wait(func() bool {
		p := r.nextHeight
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.order) == 1 && p.entries[p.order[0]].stage == deferredPending
	})
	current := k.vote(t, 0, codec.CodePrepare, view(10, 0), b)
	if !r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: current, Peer: k.addrs[1]}) {
		t.Fatal("current offer")
	}
	wait(func() bool { return len(observer.log.kinds(event.MsgOutcome)) == 1 })
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	chain.mu.Lock()
	chain.head = block(t, 10, 2, k.addrs[3], codec.BlockHash(head)).Header
	chain.vs = joined
	next := chain.head
	chain.mu.Unlock()
	r.NewHead(next)
	wait(func() bool { e, b := r.NextHeightUsage(); return e == 0 && b == 0 })
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	observer.mu.Lock()
	held := observer.held
	observer.mu.Unlock()
	if !held {
		t.Fatal("reservation was freed before core outputs completed")
	}
	if err := r.Halted(); err != nil {
		t.Fatal(err)
	}
}

// A fresh process has no old wake notification. A normal sync while the
// engine is closed must release a restored current-height frame immediately.
func TestNextHeightFreshProcessAfterNormalSync(t *testing.T) {
	k := newKeys(t, 5)
	old := nextHeightSet(t, k, []int{0, 1, 2, 3})
	joined := nextHeightSet(t, k, []int{1, 2, 3, 4})
	n := newNextHeightNode(t, k, old, types.HeightFromUint64(10), &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}, false)
	// Use a long ordinary request timer, so it cannot provide the wake that
	// this restart path itself must send.
	n.close()
	pol := uint64(0)
	n.opts.Config = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 20, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)
	n.boot()
	proposal := block(t, 11, 1, k.addrs[4], types.Hash{})
	raw := k.vote(t, 4, codec.CodePrepare, view(11, 0), proposal)
	if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodePrepare), Payload: raw, Peer: k.addrs[1]}) {
		t.Fatal("normal future offer")
	}
	n.r.Pump()
	if e, _ := n.r.NextHeightUsage(); e != 1 {
		t.Fatal("future admission missing")
	}
	n.close()
	n.chain.head = block(t, 10, 2, k.addrs[3], codec.BlockHash(n.chain.head)).Header
	n.chain.vs = joined
	clock := SystemClock()
	n.chain.clock = clock
	log, _, err := wal.Open(n.fs, "/wal", wal.Options{SegmentBytes: 2048, KeepHeights: 1})
	if err != nil {
		t.Fatal(err)
	}
	n.log = log
	n.events = &eventLog{}
	n.r, err = New(Config{Core: n.opts, ReplayWAL: true, Workers: 1, NextHeight: n.limits}, Deps{Chain: lockedNextHeightChain{n.chain}, App: &fakeApp{}, Clock: clock, WAL: log, Events: n.events})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), types.HeightFromUint64(11)); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		e, b := n.r.NextHeightUsage()
		if e == 0 && b == 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("restored current-height frame waited for an unrelated wake")
		case <-tick.C:
		}
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Halted(); err != nil {
		t.Fatal(err)
	}
	if out := n.events.kinds(event.MsgOutcome); len(out) != 1 || out[0].Fields["row"] == 2 {
		t.Fatal("restored normal new-member input not authenticated")
	}
}

// A normally signed node ahead of the local round window must not occupy
// deferred capacity that an in-window frame of the same source needs.
func TestNextHeightPreservesReceiveRoundWindow(t *testing.T) {
	k := newKeys(t, 4)
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled%t", enabled), func(t *testing.T) {
			var limits *NextHeightLimits
			if enabled {
				limits = &NextHeightLimits{Entries: 1, Bytes: 1 << 20, PerPeer: 1, PerSource: 1}
			}
			n := newNextHeightNode(t, k, k.vs, types.HeightFromUint64(10), limits, false)
			offer := func(round uint64) {
				m := &codec.Message{Code: codec.CodeRoundChange, View: view(11, round)}
				raw := k.sign(t, 0, m, nil)
				if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(m.Code), Payload: raw, Peer: k.addrs[1]}) {
					t.Fatal("normal round-change offer refused")
				}
				n.r.Pump()
			}
			offer(consensus.RoundThreshold + 1)
			if e, b := n.r.NextHeightUsage(); e != 0 || b != 0 {
				t.Fatal("out-of-window frame retained deferred capacity")
			}
			if n.r.Snapshot().Backlog != 0 {
				t.Fatal("out-of-window frame reached core backlog")
			}
			if !enabled {
				out := n.events.kinds(event.MsgOutcome)
				if len(out) != 1 || out[0].Fields["reason"] != "window" {
					t.Fatal("default receive-window outcome changed")
				}
			}
			offer(1)
			if enabled {
				if e, b := n.r.NextHeightUsage(); e != 1 || b == 0 {
					t.Fatal("in-window frame could not use released reservation")
				}
			} else if n.r.Snapshot().Backlog != 1 {
				t.Fatal("default future backlog behavior changed")
			}
		})
	}
}
