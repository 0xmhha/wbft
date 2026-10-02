package runner

import (
	"container/heap"
	"context"
	"math/big"
	"math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// ---------------------------------------------------------------- clock

type mEvent struct {
	at   time.Duration
	seq  uint64
	f    func()
	dead bool
}

type mHeap []*mEvent

func (h mHeap) Len() int { return len(h) }
func (h mHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}
func (h mHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mHeap) Push(x any)   { *h = append(*h, x.(*mEvent)) }
func (h *mHeap) Pop() any {
	o := *h
	e := o[len(o)-1]
	*h = o[:len(o)-1]
	return e
}

// manualClock fires timers only when the test advances it.
type manualClock struct {
	now time.Duration
	// tick advances the clock at each Mono call, as time passes while a
	// step runs; zero keeps it still.
	tick time.Duration
	seq  uint64
	q    mHeap
}

type mTimer struct{ e *mEvent }

func (t mTimer) Stop() bool {
	if t.e.dead {
		return false
	}
	t.e.dead = true
	return true
}

func (c *manualClock) Now() time.Time      { return time.Unix(1_700_000_000, 0).Add(c.now) }
func (c *manualClock) Mono() time.Duration { c.now += c.tick; return c.now }
func (c *manualClock) AfterFunc(d time.Duration, f func()) Timer {
	c.seq++
	e := &mEvent{at: c.now + d, seq: c.seq, f: f}
	heap.Push(&c.q, e)
	return mTimer{e}
}

// advance runs the timers due until t, in order.
func (c *manualClock) advance(t time.Duration) {
	for c.q.Len() > 0 && c.q[0].at <= t {
		e := heap.Pop(&c.q).(*mEvent)
		c.now = e.at
		if !e.dead {
			e.dead = true
			e.f()
		}
	}
	c.now = t
}

// ---------------------------------------------------------------- keys

type keys struct {
	ecdsa  []*ecdsa.PrivateKey
	bls    []*bls.SecretKey
	secret [][]byte
	addrs  []types.Address
	vs     *validator.Set
}

func newKeys(t testing.TB, n int) *keys {
	k := &keys{}
	var pubs [][]byte
	for i := 0; i < n; i++ {
		s := keccak.Sum256Bytes([]byte("wbft-runner-test-" + strconv.Itoa(i)))
		e, err := ecdsa.PrivateKeyFromBytes(s)
		if err != nil {
			t.Fatal(err)
		}
		b, err := bls.DeriveSecretKey(s)
		if err != nil {
			t.Fatal(err)
		}
		k.ecdsa, k.bls, k.secret = append(k.ecdsa, e), append(k.bls, b), append(k.secret, s)
		k.addrs = append(k.addrs, ecdsa.Address(e))
		pubs = append(pubs, b.PublicKey().Bytes())
	}
	vs, err := validator.NewSet(k.addrs, pubs, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	k.vs = vs
	return k
}

// block returns a block of a number whose content depends on tag.
func block(t testing.TB, number uint64, tag byte, coinbase types.Address, parent types.Hash) *types.Block {
	vanity := make([]byte, types.ExtraVanity)
	vanity[0] = tag
	extra, err := codec.EncodeExtra(&types.WBFTExtra{VanityData: vanity, RandaoReveal: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	return &types.Block{Header: &types.Header{ParentHash: parent, UncleHash: types.EmptyUncleHash, Coinbase: coinbase,
		Difficulty: big.NewInt(1), Number: types.HeightFromUint64(number), GasLimit: 30_000_000, Time: 1_700_000_000 + number, Extra: extra},
		Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

// sign signs m as validator i, with the seal over sealData if given.
func (k *keys) sign(t testing.TB, i int, m *codec.Message, sealData []byte) []byte {
	c := *m
	if sealData != nil {
		c.Seal = k.bls[i].Sign(sealData).Bytes()
	}
	p, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Signature, err = ecdsa.SignData(p, k.ecdsa[i]); err != nil {
		t.Fatal(err)
	}
	b, err := codec.EncodeMessage(&c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *keys) preprepare(t testing.TB, i int, v types.View, b *types.Block) []byte {
	return k.sign(t, i, &codec.Message{Code: codec.CodePreprepare, View: v, Proposal: b}, nil)
}

func (k *keys) vote(t testing.TB, i int, code codec.Code, v types.View, b *types.Block) []byte {
	st := types.PrepareSeal
	if code == codec.CodeCommit {
		st = types.CommitSeal
	}
	return k.sign(t, i, &codec.Message{Code: code, View: v, Digest: codec.BlockHash(b.Header)}, codec.SealData(b.Header, uint32(v.Round.Big().Uint64()), st))
}

func view(seq, round uint64) types.View {
	return types.View{Sequence: types.HeightFromUint64(seq), Round: types.RoundFromUint64(round)}
}

// ---------------------------------------------------------------- application

// fakeChain answers from a fixed validator set; proposals listed in future
// are from the future until the clock reaches their release time.
type fakeChain struct {
	mu     sync.Mutex
	head   *types.Header
	vs     *validator.Set
	clock  interface{ Mono() time.Duration }
	future map[types.Hash]time.Duration
	bad    map[types.Hash]bool
}

func (c *fakeChain) Head() *types.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}
func (c *fakeChain) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) { return c.vs, nil }
func (c *fakeChain) ValidateProposal(b *types.Block) (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if at, ok := c.future[codec.BlockHash(b.Header)]; ok && c.clock.Mono() < at {
		return at - c.clock.Mono(), &header.StepError{Step: "H2", Class: "ErrFutureBlock", Err: header.ErrFutureBlock}
	}
	return 0, nil
}
func (c *fakeChain) IsBadBlock(h types.Hash) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bad[h]
}

type fakeApp struct {
	mu        sync.Mutex
	builds    []consensus.RequestBuild
	finalized []*types.Block
	onFinal   func(b *types.Block)
}

func (a *fakeApp) ReadyToBuild(req consensus.RequestBuild, _ time.Duration, _ <-chan struct{}) {
	a.mu.Lock()
	a.builds = append(a.builds, req)
	a.mu.Unlock()
}
func (a *fakeApp) FinalizeBlock(b *types.Block, _ types.Round) error {
	a.mu.Lock()
	a.finalized = append(a.finalized, b)
	f := a.onFinal
	a.mu.Unlock()
	if f != nil {
		f(b)
	}
	return nil
}

// sent is a message the fake transport was asked to send.
type sent struct {
	peers   []types.Address
	code    uint64
	payload []byte
}

type fakeNet struct {
	mu     sync.Mutex
	peers  []types.Address
	sent   []sent
	discon []types.Address
}

func (n *fakeNet) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	n.mu.Lock()
	n.sent = append(n.sent, sent{append([]types.Address(nil), peers...), code, payload})
	n.mu.Unlock()
	return make([]transport.SendResult, len(peers))
}
func (n *fakeNet) SetReceiver(transport.Receiver)         {}
func (n *fakeNet) PeerEvents() <-chan transport.PeerEvent { return nil }
func (n *fakeNet) Disconnect(p types.Address, _ string) {
	n.mu.Lock()
	n.discon = append(n.discon, p)
	n.mu.Unlock()
}
func (n *fakeNet) Peers() []transport.PeerInfo {
	var out []transport.PeerInfo
	for _, p := range n.peers {
		out = append(out, transport.PeerInfo{Addr: p})
	}
	return out
}

// own returns the payloads sent with code.
func (n *fakeNet) own(code codec.Code) [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out [][]byte
	for _, s := range n.sent {
		if s.code == uint64(code) {
			out = append(out, s.payload)
		}
	}
	return out
}

// eventLog keeps the event records.
type eventLog struct {
	mu     sync.Mutex
	recs   []event.Record
	stamps []event.Stamp // of recs, by index
}

func (l *eventLog) Write(r event.Record, at event.Stamp) error {
	l.mu.Lock()
	l.recs, l.stamps = append(l.recs, r), append(l.stamps, at)
	l.mu.Unlock()
	return nil
}

func (l *eventLog) kinds(k event.Kind) []event.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []event.Record
	for _, r := range l.recs {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------- node

// tnode is one runner in manual mode on a memory file system.
type tnode struct {
	t      *testing.T
	k      *keys
	self   int
	fs     *fsys.Mem
	clock  *manualClock
	chain  *fakeChain
	app    *fakeApp
	net    *fakeNet
	events *eventLog
	jfs    *fsys.Mem
	r      *Runner
	signer *privval.FileSigner
	log    *wal.Log
	opts   consensus.Options
	// noJournal boots the runner without a message journal.
	noJournal bool
}

func newTNode(t *testing.T, k *keys, self int) *tnode {
	n := &tnode{t: t, k: k, self: self, fs: fsys.NewMem(), clock: &manualClock{}, jfs: fsys.NewMem()}
	pol := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}, nil, types.GenesisInit{}, nil)
	n.opts = consensus.Options{Config: cfg, Self: k.addrs[self], Improvements: consensus.RestartSafety}
	// The head is block 9 of the last validator, so the proposer of (10, r)
	// is validator r mod n.
	n.chain = &fakeChain{head: block(t, 9, 0, k.addrs[len(k.addrs)-1], types.Hash{}).Header, vs: k.vs, clock: n.clock,
		future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}
	n.app = &fakeApp{}
	n.net = &fakeNet{}
	for i, a := range k.addrs {
		if i != self {
			n.net.peers = append(n.net.peers, a)
		}
	}
	return n
}

// boot opens the logs and the signer and starts a runner (a process start).
func (n *tnode) boot() {
	t := n.t
	if err := n.fs.MkdirAll("/pv", 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := privval.NewKeySigner(n.fs, nil, n.k.secret[n.self], "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	n.signer = s
	log, _, err := wal.Open(n.fs, "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n.log = log
	dd, err := transport.NewDedup(n.net, transport.DedupOptions{Self: n.k.addrs[n.self]})
	if err != nil {
		t.Fatal(err)
	}
	jw, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/j", Synchronous: true}, journal.Identity{Self: n.k.addrs[n.self]})
	if err != nil {
		t.Fatal(err)
	}
	n.events = &eventLog{}
	d := Deps{Chain: n.chain, App: n.app, Transport: dd, Net: n.net,
		Signer: s, WAL: log, Clock: n.clock, Events: n.events, Journal: jw, Rand: rand.New(rand.NewPCG(1, 2)).IntN}
	if n.noJournal {
		d.Journal = nil
	}
	r, err := New(Config{Core: n.opts, ReplayWAL: true, Manual: true}, d)
	if err != nil {
		t.Fatal(err)
	}
	n.r = r
	if err := r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	r.Pump()
}

// crash drops the runner and what was not synced.
func (n *tnode) crash() {
	n.r = nil
	n.fs.Crash(nil)
	n.clock.q = nil
}

// deliver offers a message from validator peer and pumps.
func (n *tnode) deliver(peer int, code codec.Code, payload []byte) {
	n.r.Receiver().Offer(transport.Inbound{Peer: n.k.addrs[peer], Code: uint64(code), Payload: payload, RecvMono: n.clock.now})
	n.r.Pump()
}

func (n *tnode) advance(d time.Duration) {
	n.clock.advance(n.clock.now + d)
	n.r.Pump()
}

func transportInbound(k *keys, peer int, code codec.Code, payload []byte, at time.Duration) transport.Inbound {
	return transport.Inbound{Peer: k.addrs[peer], Code: uint64(code), Payload: payload, RecvMono: at}
}
