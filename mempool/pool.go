package mempool

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/0xmhha/wbft/types"
)

// Config bounds a TxPool. Zero values use the defaults.
type Config struct {
	// MaxTxs bounds the number of pooled transactions (default 6144).
	MaxTxs int
	// MaxBytes bounds their total size (default 64 MiB).
	MaxBytes int
	// MaxPerSender bounds the transactions of one sender (default 64).
	MaxPerSender int
	// PeerQueue bounds the transactions of one peer waiting for admission
	// (default 1024).
	PeerQueue int
	// Logger logs; nil discards.
	Logger *slog.Logger
}

// Errors of the pool.
var (
	ErrStopped = errors.New("mempool: stopped")
	ErrNoHook  = errors.New("mempool: an admission hook is required")
)

// Reasons of the rejections the pool itself decides.
const (
	ReasonKnown       = "already known"
	ReasonNonceLow    = "nonce too low"
	ReasonReplacement = "replacement not allowed"
	ReasonSenderFull  = "sender limit reached"
	ReasonPoolFull    = "pool is full"
	ReasonBadKey      = "invalid transaction key"
)

// TxPool is the transaction pool. Admission runs on one goroutine, in the
// order transactions arrive; a recheck after a new head runs on the same
// goroutine before any later admission, so that new transactions are
// checked against the new head.
type TxPool struct {
	cfg    Config
	hook   AdmissionHook
	policy OrderingPolicy
	tx     TxTransport
	log    *slog.Logger

	mu       sync.Mutex
	byKey    map[types.Hash]*PooledTx
	senders  map[types.Address]*senderList
	arrival  uint64
	bytes    int
	subs     map[int]chan<- []types.Hash
	subSeq   int
	peerLoad map[types.Address]int
	update   *BlockUpdate // latest update whose recheck has not started
	gen      uint64       // bumped by every Update; a recheck of an older one stops
	running  bool

	jobs   chan job
	wake   chan struct{}
	stop   chan struct{}
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

var _ Pool = (*TxPool)(nil)

var _ TxReceiver = (*TxPool)(nil)

type senderList struct {
	stateNonce uint64
	byNonce    map[uint64]*PooledTx
}

// executable returns the transactions from the state nonce without a gap.
func (s *senderList) executable() []*PooledTx {
	var out []*PooledTx
	for n := s.stateNonce; ; n++ {
		tx := s.byNonce[n]
		if tx == nil {
			return out
		}
		out = append(out, tx)
	}
}

// sorted returns every transaction of the sender in nonce order.
func (s *senderList) sorted() []*PooledTx {
	ns := slices.Sorted(maps.Keys(s.byNonce))
	out := make([]*PooledTx, len(ns))
	for i, n := range ns {
		out[i] = s.byNonce[n]
	}
	return out
}

type job struct {
	tx     []byte
	origin Origin
	peer   types.Address
	reply  chan CheckResponse // nil for remote transactions
}

// New returns a pool that is not started.
func New(cfg Config, hook AdmissionHook, policy OrderingPolicy, tx TxTransport) (*TxPool, error) {
	if hook == nil {
		return nil, ErrNoHook
	}
	if policy == nil {
		policy = fifo{}
	}
	if cfg.MaxTxs <= 0 {
		cfg.MaxTxs = 6144
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 64 << 20
	}
	if cfg.MaxPerSender <= 0 {
		cfg.MaxPerSender = 64
	}
	if cfg.PeerQueue <= 0 {
		cfg.PeerQueue = 1024
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &TxPool{cfg: cfg, hook: hook, policy: policy, tx: tx, log: log,
		byKey: map[types.Hash]*PooledTx{}, senders: map[types.Address]*senderList{}, subs: map[int]chan<- []types.Hash{},
		peerLoad: map[types.Address]int{}, jobs: make(chan job, 4096), wake: make(chan struct{}, 1)}, nil
}

// Start starts the admission goroutine and installs the pool as the
// receiver of the transaction transport.
func (p *TxPool) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return errors.New("mempool: already started")
	}
	p.running = true
	p.ctx, p.cancel = context.WithCancel(context.WithoutCancel(ctx))
	p.stop, p.done = make(chan struct{}), make(chan struct{})
	p.mu.Unlock()
	go p.loop()
	if p.tx != nil {
		p.tx.SetTxReceiver(p)
	}
	return nil
}

// Stop ends the admission goroutine. Pending local additions return
// ErrStopped.
func (p *TxPool) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	p.mu.Unlock()
	close(p.stop)
	p.cancel()
	<-p.done
}

func (p *TxPool) loop() {
	defer close(p.done)
	for {
		p.recheck()
		select {
		case <-p.stop:
			return
		case <-p.wake:
		case j := <-p.jobs:
			p.admit(j)
		}
	}
}

// Add implements Pool.
func (p *TxPool) Add(ctx context.Context, tx []byte) (CheckResponse, error) {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return CheckResponse{}, ErrStopped
	}
	stop := p.stop
	p.mu.Unlock()
	j := job{tx: tx, origin: OriginLocal, reply: make(chan CheckResponse, 1)}
	select {
	case p.jobs <- j:
	case <-stop:
		return CheckResponse{}, ErrStopped
	case <-ctx.Done():
		return CheckResponse{}, ctx.Err()
	}
	select {
	case r := <-j.reply:
		return r, nil
	case <-stop:
		return CheckResponse{}, ErrStopped
	case <-ctx.Done():
		return CheckResponse{}, ctx.Err()
	}
}

// OfferTxs implements TxReceiver.
func (p *TxPool) OfferTxs(peer types.Address, txs [][]byte) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return 0
	}
	n := 0
	for _, tx := range txs {
		if p.peerLoad[peer] >= p.cfg.PeerQueue {
			break
		}
		select {
		case p.jobs <- job{tx: tx, origin: OriginRemote, peer: peer}:
			p.peerLoad[peer]++
			n++
		default:
			return n
		}
	}
	return n
}

// admit checks one transaction and adds it.
func (p *TxPool) admit(j job) {
	resp := p.check(j)
	if j.reply != nil {
		j.reply <- resp
	}
}

func (p *TxPool) check(j job) CheckResponse {
	if j.origin == OriginRemote {
		p.mu.Lock()
		if p.peerLoad[j.peer]--; p.peerLoad[j.peer] <= 0 {
			delete(p.peerLoad, j.peer)
		}
		p.mu.Unlock()
	}
	key, err := p.hook.TxKey(j.tx)
	if err != nil {
		return CheckResponse{Code: CodeReject, Reason: ReasonBadKey}
	}
	if p.Has(key) {
		return CheckResponse{Code: CodeReject, Reason: ReasonKnown}
	}
	resp := p.hook.CheckTx(p.ctx, CheckRequest{Tx: j.tx, Key: key, Kind: CheckNew, Origin: j.origin})
	if resp.Code != CodeOK {
		return resp
	}
	meta := resp.Meta
	if meta.Size == 0 {
		meta.Size = len(j.tx)
	}
	if reason := p.insert(key, j.tx, meta, j.origin == OriginLocal); reason != "" {
		return CheckResponse{Code: CodeReject, Reason: reason}
	}
	p.publish(OutTx{Key: key, Tx: j.tx, Meta: meta})
	return resp
}

// insert adds a checked transaction; it returns the reason of a rejection
// or "".
func (p *TxPool) insert(key types.Hash, tx []byte, meta TxMeta, local bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	// The check read the head state: its state nonce applies to the
	// sender's pooled transactions even when this one is rejected.
	s := p.senders[meta.Sender]
	if s != nil {
		p.setStateNonce(meta.Sender, s, meta.StateNonce)
	}
	if meta.Nonce < meta.StateNonce {
		return ReasonNonceLow
	}
	if s == nil {
		s = &senderList{byNonce: map[uint64]*PooledTx{}}
	}
	if meta.StateNonce > s.stateNonce {
		s.stateNonce = meta.StateNonce
	}
	if old := s.byNonce[meta.Nonce]; old != nil {
		if !p.policy.Replace(old.Meta, meta) {
			return ReasonReplacement
		}
		p.removeLocked(old.Key)
	}
	// Raising the state nonce or a replacement may have emptied the list
	// and removed it from the table.
	p.senders[meta.Sender] = s
	if len(s.byNonce) >= p.cfg.MaxPerSender {
		return ReasonSenderFull
	}
	p.arrival++
	ptx := &PooledTx{Key: key, Tx: tx, Meta: meta, Arrival: p.arrival, Local: local}
	s.byNonce[meta.Nonce] = ptx
	p.byKey[key] = ptx
	p.bytes += meta.Size
	if excess := len(p.byKey) - p.cfg.MaxTxs; excess > 0 || p.bytes > p.cfg.MaxBytes {
		if excess < 1 {
			excess = 1
		}
		for _, k := range p.policy.Evict(p.statsLocked(), excess) {
			p.removeLocked(k)
		}
		for p.bytes > p.cfg.MaxBytes && len(p.byKey) > 0 {
			// The policy freed too little; drop the latest arrival.
			st := p.statsLocked()
			p.removeLocked(st.Txs[len(st.Txs)-1].Key)
		}
		if p.byKey[key] == nil {
			return ReasonPoolFull
		}
	}
	return ""
}

// setStateNonce raises the state nonce of a sender and drops the
// transactions below it.
func (p *TxPool) setStateNonce(addr types.Address, s *senderList, n uint64) {
	if n <= s.stateNonce {
		return
	}
	s.stateNonce = n
	for nonce, tx := range s.byNonce { //wbft:unordered each transaction is tested alone
		if nonce < n {
			p.removeLocked(tx.Key)
		}
	}
	if len(s.byNonce) == 0 {
		delete(p.senders, addr)
	}
}

func (p *TxPool) removeLocked(key types.Hash) {
	tx := p.byKey[key]
	if tx == nil {
		return
	}
	delete(p.byKey, key)
	p.bytes -= tx.Meta.Size
	if s := p.senders[tx.Meta.Sender]; s != nil {
		delete(s.byNonce, tx.Meta.Nonce)
		if len(s.byNonce) == 0 {
			delete(p.senders, tx.Meta.Sender)
		}
	}
}

func (p *TxPool) statsLocked() PoolStats {
	txs := make([]PooledTx, 0, len(p.byKey))
	for _, tx := range p.byKey { //wbft:unordered sorted below
		txs = append(txs, *tx)
	}
	slices.SortFunc(txs, func(a, b PooledTx) int {
		switch {
		case a.Arrival < b.Arrival:
			return -1
		case a.Arrival > b.Arrival:
			return 1
		}
		return 0
	})
	return PoolStats{Txs: txs, Bytes: p.bytes}
}

// publish announces an admitted transaction to the transport and the
// subscribers.
func (p *TxPool) publish(out OutTx) {
	if p.tx != nil {
		p.tx.Propagate([]OutTx{out})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ch := range p.subs { //wbft:unordered every subscriber gets the key
		select {
		case ch <- []types.Hash{out.Key}:
		default:
		}
	}
}

// Update implements Pool.
func (p *TxPool) Update(_ context.Context, u BlockUpdate) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := map[types.Address]uint64{}
	for _, k := range u.Included {
		tx := p.byKey[k]
		if tx == nil {
			continue
		}
		if n := tx.Meta.Nonce + 1; n > next[tx.Meta.Sender] {
			next[tx.Meta.Sender] = n
		}
		p.removeLocked(k)
	}
	for _, addr := range slices.SortedFunc(maps.Keys(next), types.Address.Cmp) {
		if s := p.senders[addr]; s != nil {
			p.setStateNonce(addr, s, next[addr])
		}
	}
	p.gen++
	uc := u
	p.update = &uc
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}

// recheck checks the pooled transactions again after the latest update.
// It stops when a newer update arrives; the loop then starts over.
func (p *TxPool) recheck() {
	for {
		p.mu.Lock()
		u, gen := p.update, p.gen
		p.update = nil
		var senders []types.Address
		if u != nil {
			if sc, ok := p.hook.(RecheckScoper); ok {
				senders = sc.Scope(*u)
			} else {
				senders = slices.SortedFunc(maps.Keys(p.senders), types.Address.Cmp)
			}
		}
		p.mu.Unlock()
		if u == nil {
			return
		}
		p.recheckSenders(senders, gen)
	}
}

func (p *TxPool) recheckSenders(senders []types.Address, gen uint64) {
	for _, addr := range senders {
		p.mu.Lock()
		s := p.senders[addr]
		var txs []*PooledTx
		if s != nil {
			txs = s.sorted()
		}
		p.mu.Unlock()
		for _, tx := range txs {
			p.mu.Lock()
			stale := p.gen != gen
			p.mu.Unlock()
			if stale {
				return
			}
			resp := p.hook.CheckTx(p.ctx, CheckRequest{Tx: tx.Tx, Key: tx.Key, Kind: CheckRecheck, Origin: origin(tx.Local)})
			p.mu.Lock()
			switch {
			case p.byKey[tx.Key] != tx:
				// Removed or replaced meanwhile.
			case resp.Code != CodeOK:
				p.removeLocked(tx.Key)
			default:
				if s := p.senders[addr]; s != nil {
					p.setStateNonce(addr, s, resp.Meta.StateNonce)
				}
			}
			p.mu.Unlock()
		}
	}
}

func origin(local bool) Origin {
	if local {
		return OriginLocal
	}
	return OriginRemote
}

// Proposal implements Pool.
func (p *TxPool) Proposal(_ context.Context, req ProposalRequest) (ProposalIter, error) {
	p.mu.Lock()
	heads := make([]SenderHead, 0, len(p.senders))
	for _, addr := range slices.SortedFunc(maps.Keys(p.senders), types.Address.Cmp) {
		exec := p.senders[addr].executable()
		if len(exec) == 0 {
			continue
		}
		h := SenderHead{Sender: addr, Txs: make([]PooledTx, len(exec))}
		for i, tx := range exec {
			h.Txs[i] = *tx
		}
		heads = append(heads, h)
	}
	p.mu.Unlock()
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultProposalBytes
	}
	return &proposalIter{it: p.policy.NewIterator(heads, req.Env), env: req.Env, maxGas: req.MaxGas, maxBytes: maxBytes}, nil
}

// proposalIter applies the bounds and the environment filter to a policy
// iterator.
type proposalIter struct {
	it       Iterator
	env      ProposalEnv
	maxGas   uint64
	maxBytes int
	gas      uint64
	bytes    int
	last     *PooledTx // handed out and not reported yet
}

func (pi *proposalIter) Next() (types.Hash, []byte, TxMeta, bool) {
	if pi.last != nil {
		pi.it.Report(pi.last.Key, Included)
		pi.last = nil
	}
	for {
		tx, ok := pi.it.Next()
		if !ok {
			return types.Hash{}, nil, TxMeta{}, false
		}
		// A transaction that does not fit or that the environment excludes
		// ends its sender: the later nonces cannot follow.
		if pi.env != nil && !pi.env.Include(tx.Meta) ||
			pi.maxGas > 0 && pi.gas+tx.Meta.GasLimit > pi.maxGas ||
			pi.bytes+tx.Meta.Size > pi.maxBytes {
			pi.it.Report(tx.Key, DropSender)
			continue
		}
		pi.gas += tx.Meta.GasLimit
		pi.bytes += tx.Meta.Size
		pi.last = &tx
		return tx.Key, tx.Tx, tx.Meta, true
	}
}

func (pi *proposalIter) Report(key types.Hash, out ExecOutcome) {
	if pi.last == nil || pi.last.Key != key {
		return
	}
	if out != Included {
		pi.gas -= pi.last.Meta.GasLimit
		pi.bytes -= pi.last.Meta.Size
	}
	pi.it.Report(key, out)
	pi.last = nil
}

// Get implements Pool.
func (p *TxPool) Get(keys []types.Hash) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(keys))
	for i, k := range keys {
		if tx := p.byKey[k]; tx != nil {
			out[i] = tx.Tx
		}
	}
	return out
}

// Has implements Pool.
func (p *TxPool) Has(key types.Hash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.byKey[key] != nil
}

// PendingNonce implements Pool.
func (p *TxPool) PendingNonce(sender types.Address) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.senders[sender]
	if s == nil {
		return 0, false
	}
	return s.stateNonce + uint64(len(s.executable())), true
}

// Content implements Pool.
func (p *TxPool) Content(sender *types.Address) PoolContent {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := PoolContent{Pending: map[types.Address][]PooledTx{}, Queued: map[types.Address][]PooledTx{}}
	for addr, s := range p.senders { //wbft:unordered the result is a map
		if sender != nil && addr != *sender {
			continue
		}
		exec := s.executable()
		for i, tx := range s.sorted() {
			if i < len(exec) {
				c.Pending[addr] = append(c.Pending[addr], *tx)
			} else {
				c.Queued[addr] = append(c.Queued[addr], *tx)
			}
		}
	}
	return c
}

// SubscribeNew implements Pool. A subscriber that is not ready misses
// keys.
func (p *TxPool) SubscribeNew(ch chan<- []types.Hash) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := p.subSeq
	p.subSeq++
	p.subs[id] = ch
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.subs, id)
	}
}
