package mempool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// testHook admits transactions of the form [sender, nonce, tag]. The state
// nonce of a sender and a blacklist are set by the test.
type testHook struct {
	mu     sync.Mutex
	state  map[types.Address]uint64
	banned map[types.Address]bool
	checks []CheckRequest
}

func newHook() *testHook {
	return &testHook{state: map[types.Address]uint64{}, banned: map[types.Address]bool{}}
}

func tx(sender byte, nonce uint64, tag byte) []byte { return []byte{sender, byte(nonce), tag} }

func addr(b byte) types.Address { return types.Address{b} }

func (h *testHook) TxKey(tx []byte) (types.Hash, error) {
	if len(tx) != 3 {
		return types.Hash{}, errors.New("bad tx")
	}
	return keccak.Sum256(tx), nil
}

func (h *testHook) CheckTx(_ context.Context, req CheckRequest) CheckResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks = append(h.checks, req)
	s := addr(req.Tx[0])
	if h.banned[s] {
		return CheckResponse{Code: CodeReject, Reason: "banned"}
	}
	return CheckResponse{Code: CodeOK, Meta: TxMeta{Sender: s, Nonce: uint64(req.Tx[1]), StateNonce: h.state[s], GasLimit: 10}}
}

func (h *testHook) set(f func(*testHook)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f(h)
}

func newPool(t *testing.T, cfg Config, h AdmissionHook, tr TxTransport) *TxPool {
	t.Helper()
	p, err := New(cfg, h, nil, tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	return p
}

func mustAdd(t *testing.T, p *TxPool, b []byte, want CheckCode, reason string) {
	t.Helper()
	r, err := p.Add(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != want || r.Reason != reason {
		t.Fatalf("add %v: %d %q, want %d %q", b, r.Code, r.Reason, want, reason)
	}
}

func nonces(txs []PooledTx) []uint64 {
	out := []uint64{}
	for _, tx := range txs {
		out = append(out, tx.Meta.Nonce)
	}
	return out
}

func eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNonceLists(t *testing.T) {
	h := newHook()
	p := newPool(t, Config{}, h, nil)
	a := addr(1)
	mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 2, 0), CodeOK, "")
	c := p.Content(&a)
	if !eq(nonces(c.Pending[a]), []uint64{0}) || !eq(nonces(c.Queued[a]), []uint64{2}) {
		t.Fatalf("pending %v queued %v", nonces(c.Pending[a]), nonces(c.Queued[a]))
	}
	mustAdd(t, p, tx(1, 1, 0), CodeOK, "")
	if n, ok := p.PendingNonce(a); !ok || n != 3 {
		t.Fatalf("pending nonce %d %v", n, ok)
	}
	mustAdd(t, p, tx(1, 1, 0), CodeReject, ReasonKnown)
	mustAdd(t, p, tx(1, 1, 9), CodeReject, ReasonReplacement) // fifo keeps the first
	h.set(func(h *testHook) { h.state[a] = 5 })
	mustAdd(t, p, tx(1, 3, 0), CodeReject, ReasonNonceLow)
	// The admission raised the state nonce: the lower nonces are gone.
	if c := p.Content(&a); len(c.Pending[a])+len(c.Queued[a]) != 0 {
		t.Fatalf("left %v %v", c.Pending[a], c.Queued[a])
	}
	mustAdd(t, p, []byte{1}, CodeReject, ReasonBadKey)
}

func TestProposalOrder(t *testing.T) {
	h := newHook()
	p := newPool(t, Config{}, h, nil)
	for _, b := range [][]byte{tx(2, 0, 0), tx(1, 0, 0), tx(2, 1, 0), tx(1, 1, 0), tx(3, 5, 0)} {
		mustAdd(t, p, b, CodeOK, "")
	}
	it, err := p.Proposal(context.Background(), ProposalRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// Sender 2 arrived first; sender 3 has a gap and is not executable.
	var got []string
	for {
		k, b, _, ok := it.Next()
		if !ok {
			break
		}
		got = append(got, string(rune('0'+b[0]))+string(rune('0'+b[1])))
		if b[0] == 2 && b[1] == 0 {
			it.Report(k, DropSender) // skips 2/1
		}
	}
	if want := []string{"20", "10", "11"}; !equalS(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}

	// Byte bound: each transaction is 3 bytes.
	it, _ = p.Proposal(context.Background(), ProposalRequest{MaxBytes: 7})
	n := 0
	for _, _, _, ok := it.Next(); ok; _, _, _, ok = it.Next() {
		n++
	}
	if n != 2 {
		t.Fatalf("%d transactions under 7 bytes", n)
	}
}

func equalS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestUpdateAndRecheck(t *testing.T) {
	h := newHook()
	p := newPool(t, Config{}, h, nil)
	for _, b := range [][]byte{tx(1, 0, 0), tx(1, 1, 0), tx(1, 2, 0), tx(2, 0, 0)} {
		mustAdd(t, p, b, CodeOK, "")
	}
	k0, _ := h.TxKey(tx(1, 0, 0))
	h.set(func(h *testHook) { h.state[addr(1)] = 1; h.banned[addr(2)] = true })
	if err := p.Update(context.Background(), BlockUpdate{Included: []types.Hash{k0}}); err != nil {
		t.Fatal(err)
	}
	// A local addition queues behind the recheck, so when it returns the
	// recheck is done.
	mustAdd(t, p, tx(3, 0, 0), CodeOK, "")
	if p.Has(k0) {
		t.Fatal("included transaction kept")
	}
	k2, _ := h.TxKey(tx(2, 0, 0))
	if p.Has(k2) {
		t.Fatal("banned sender kept after recheck")
	}
	a := addr(1)
	if c := p.Content(&a); !eq(nonces(c.Pending[a]), []uint64{1, 2}) {
		t.Fatalf("pending %v", nonces(c.Pending[a]))
	}
	rechecks := 0
	h.set(func(h *testHook) {
		for _, c := range h.checks {
			if c.Kind == CheckRecheck {
				rechecks++
			}
		}
	})
	if rechecks != 3 {
		t.Fatalf("%d rechecks, want 3", rechecks)
	}
}

// scopedHook limits the recheck to scope and counts the updates it saw.
type scopedHook struct {
	*testHook
	scope   RecheckScope
	updates int
}

func (h *scopedHook) Scope(BlockUpdate) RecheckScope {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.updates++
	return h.scope
}

// TestRecheckScope: a scoper rechecks every sender with All, none with an
// empty scope (also a nil list) and only the listed senders otherwise.
func TestRecheckScope(t *testing.T) {
	for _, c := range []struct {
		name  string
		scope RecheckScope
		kept  []byte // senders left after the recheck
	}{
		{"all", RecheckScope{All: true}, []byte{}},
		{"none", RecheckScope{}, []byte{1, 2}},
		{"empty", RecheckScope{Senders: []types.Address{}}, []byte{1, 2}},
		{"one", RecheckScope{Senders: []types.Address{addr(2)}}, []byte{1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &scopedHook{testHook: newHook(), scope: c.scope}
			p := newPool(t, Config{}, h, nil)
			mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
			mustAdd(t, p, tx(2, 0, 0), CodeOK, "")
			h.set(func(h *testHook) { h.banned[addr(1)] = true; h.banned[addr(2)] = true })
			if err := p.Update(context.Background(), BlockUpdate{}); err != nil {
				t.Fatal(err)
			}
			// A local addition queues behind the recheck.
			mustAdd(t, p, tx(3, 0, 0), CodeOK, "")
			kept := []byte{}
			for _, s := range []byte{1, 2} {
				if k, _ := h.TxKey(tx(s, 0, 0)); p.Has(k) {
					kept = append(kept, s)
				}
			}
			if string(kept) != string(c.kept) || h.updates != 1 {
				t.Fatalf("kept senders %v, want %v; %d updates seen", kept, c.kept, h.updates)
			}
		})
	}
}

// metaHook answers each check with a gas limit that counts the checks, so
// the admission meta can be told from a recheck's.
type metaHook struct{ *testHook }

func (h metaHook) CheckTx(ctx context.Context, req CheckRequest) CheckResponse {
	r := h.testHook.CheckTx(ctx, req)
	h.mu.Lock()
	r.Meta.GasLimit = uint64(len(h.checks))
	h.mu.Unlock()
	return r
}

// TestRecheckPrev: a recheck carries the meta of the admission (not that of
// an earlier recheck); a first check carries none.
func TestRecheckPrev(t *testing.T) {
	h := metaHook{newHook()}
	p := newPool(t, Config{}, h, nil)
	mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
	for i := range 2 {
		if err := p.Update(context.Background(), BlockUpdate{}); err != nil {
			t.Fatal(err)
		}
		mustAdd(t, p, tx(byte(2+i), 0, 0), CodeOK, "") // queues behind the recheck
	}
	h.set(func(h *testHook) {
		var prevs []uint64
		for _, c := range h.checks {
			switch {
			case c.Kind == CheckNew && c.Prev != nil:
				t.Fatalf("first check of %v carries %+v", c.Tx, *c.Prev)
			case c.Kind == CheckRecheck && c.Tx[0] == 1:
				if c.Prev == nil || c.Prev.Sender != addr(1) {
					t.Fatalf("recheck without the admission meta: %+v", c.Prev)
				}
				prevs = append(prevs, c.Prev.GasLimit)
			}
		}
		if len(prevs) != 2 || prevs[0] != 1 || prevs[1] != 1 {
			t.Fatalf("recheck gas limits of the kept meta %v, want [1 1] (the admission)", prevs)
		}
	})
}

func TestLimits(t *testing.T) {
	h := newHook()
	p := newPool(t, Config{MaxTxs: 2, MaxPerSender: 2}, h, nil)
	mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 1, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 2, 0), CodeReject, ReasonSenderFull)
	mustAdd(t, p, tx(2, 0, 0), CodeReject, ReasonPoolFull) // fifo evicts the newest
	if len(p.Content(nil).Pending[addr(1)]) != 2 {
		t.Fatal("older transactions evicted")
	}
}

type testTransport struct {
	r   TxReceiver
	out chan OutTx
}

func (t *testTransport) SetTxReceiver(r TxReceiver) { t.r = r }
func (t *testTransport) Propagate(txs []OutTx) {
	for _, tx := range txs {
		t.out <- tx
	}
}

func TestRemoteAndGossip(t *testing.T) {
	h := newHook()
	tr := &testTransport{out: make(chan OutTx, 16)}
	p := newPool(t, Config{PeerQueue: 2}, h, tr)
	sub := make(chan []types.Hash, 16)
	defer p.SubscribeNew(sub)()
	if n := tr.r.OfferTxs(addr(9), [][]byte{tx(1, 0, 0), tx(1, 1, 0), tx(1, 2, 0)}); n > 2 {
		t.Fatalf("%d queued over the peer limit", n)
	}
	for range 2 {
		select {
		case o := <-tr.out:
			if !p.Has(o.Key) {
				t.Fatal("propagated a transaction the pool does not hold")
			}
			<-sub
		case <-time.After(5 * time.Second):
			t.Fatal("no propagation")
		}
	}
	h.set(func(h *testHook) {
		for _, c := range h.checks {
			if c.Origin != OriginRemote {
				t.Errorf("origin %d", c.Origin)
			}
		}
	})
	got := p.Get([]types.Hash{keccak.Sum256(tx(1, 0, 0)), {}})
	if got[0] == nil || got[1] != nil {
		t.Fatalf("get %v", got)
	}
}

func TestStopped(t *testing.T) {
	p, err := New(Config{}, newHook(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(context.Background(), tx(1, 0, 0)); !errors.Is(err, ErrStopped) {
		t.Fatalf("add before start: %v", err)
	}
	if _, err := New(Config{}, nil, nil, nil); !errors.Is(err, ErrNoHook) {
		t.Fatalf("no hook: %v", err)
	}
}

func TestRegistry(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if p, err := r.Get(FIFO); err != nil || p.Name() != FIFO {
		t.Fatalf("fifo: %v", err)
	}
	if _, err := r.Get("stablenet"); !errors.Is(err, ErrUnknownPolicy) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := NewRegistry(fifo{}); !errors.Is(err, ErrDuplicatePolicy) {
		t.Fatalf("duplicate: %v", err)
	}
}

// TestSizes counts executable and queued transactions and their bytes.
func TestSizes(t *testing.T) {
	p := newPool(t, Config{}, newHook(), nil)
	mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 1, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 3, 0), CodeOK, "") // gap at 2: queued
	mustAdd(t, p, tx(2, 0, 0), CodeOK, "")
	if s := p.Sizes(); s != (PoolSizes{ExecTxs: 3, ExecBytes: 9, QueuedTxs: 1, QueuedBytes: 3}) {
		t.Fatalf("sizes %+v", s)
	}
	mustAdd(t, p, tx(1, 2, 0), CodeOK, "") // fills the gap
	if s := p.Sizes(); s != (PoolSizes{ExecTxs: 5, ExecBytes: 15}) {
		t.Fatalf("sizes after the gap %+v", s)
	}
}

// countObserver records what a pool reports.
type countObserver struct {
	mu       sync.Mutex
	checks   map[string]int
	rechecks int
	dropped  int
}

func (o *countObserver) Checked(code CheckCode, origin Origin, kind CheckKind) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.checks == nil {
		o.checks = map[string]int{}
	}
	o.checks[fmt.Sprintf("%d/%d/%d", code, origin, kind)]++
}
func (o *countObserver) Rechecked(time.Duration) { o.mu.Lock(); o.rechecks++; o.mu.Unlock() }
func (o *countObserver) InboundDropped(n int)    { o.mu.Lock(); o.dropped += n; o.mu.Unlock() }

// TestObserver reports each admission and recheck result with its origin
// and kind, a finished recheck, and peer transactions the pool did not
// queue.
func TestObserver(t *testing.T) {
	obs := &countObserver{}
	h := newHook()
	p := newPool(t, Config{PeerQueue: 1, Observer: obs}, h, nil)
	mustAdd(t, p, tx(1, 0, 0), CodeOK, "")
	mustAdd(t, p, tx(1, 0, 0), CodeReject, ReasonKnown)
	// The peer's queue holds one transaction: the other two are dropped.
	if n := p.OfferTxs(addr(9), [][]byte{tx(2, 0, 0), tx(2, 1, 0), tx(2, 2, 0)}); n != 1 {
		t.Fatalf("queued %d of 3", n)
	}
	// Wait for its admission, so that the recheck below sees it.
	remote, _ := h.TxKey(tx(2, 0, 0))
	for deadline := time.Now().Add(5 * time.Second); !p.Has(remote); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the peer's transaction was not admitted")
		}
	}
	h.set(func(h *testHook) { h.banned[addr(1)] = true })
	if err := p.Update(context.Background(), BlockUpdate{}); err != nil {
		t.Fatal(err)
	}
	// A local addition queues behind the recheck, so the recheck is done
	// when it returns.
	mustAdd(t, p, tx(3, 0, 0), CodeOK, "")
	obs.mu.Lock()
	defer obs.mu.Unlock()
	k := func(c CheckCode, o Origin, kind CheckKind) string { return fmt.Sprintf("%d/%d/%d", c, o, kind) }
	want := map[string]int{
		k(CodeOK, OriginLocal, CheckNew):         2,
		k(CodeReject, OriginLocal, CheckNew):     1,
		k(CodeOK, OriginRemote, CheckNew):        1,
		k(CodeReject, OriginLocal, CheckRecheck): 1,
		k(CodeOK, OriginRemote, CheckRecheck):    1,
	}
	if fmt.Sprint(obs.checks) != fmt.Sprint(want) || obs.rechecks != 1 || obs.dropped != 2 {
		t.Fatalf("checks %v (want %v), %d rechecks, %d dropped", obs.checks, want, obs.rechecks, obs.dropped)
	}
}
