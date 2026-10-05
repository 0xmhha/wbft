package runner

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// inbox is the peer side of the input: a bounded receive queue per peer
// that the transport's read loops fill without blocking, receive-check
// workers that decode, recover signers and filter by membership and view
// window, and a table of slots keyed by (sender, sequence, round, code)
// from which the consensus goroutine takes one message per peer in turn. A
// newer message of the same sender and slot overwrites an older one that
// was not taken yet; round-0 PRE-PREPAREs have two slots so that the first
// one is kept.
type inbox struct {
	r     *Runner
	mu    sync.Mutex // runner.inbox.mu
	cond  *sync.Cond
	peers map[types.Address]*peerIn
	order []types.Address // peers in the order they were first seen
	wIdx  int             // worker turn
	cIdx  int             // consensus turn
	slots map[slotKey]*slot
}

type peerIn struct {
	q     []transport.Inbound
	bytes int64
	ready []slotKey
	drops []time.Duration
}

type slotKey struct {
	src        types.Address
	seq, round string
	code       codec.Code
	second     bool
}

type slot struct {
	in     transport.Inbound
	dedup  types.Hash
	digest types.Hash
	sig    []byte
	source types.Address
	ready  types.Address // the peer whose ready list holds the slot key
}

func (b *inbox) init(r *Runner) {
	b.r = r
	b.cond = sync.NewCond(&b.mu)
	b.peers = map[types.Address]*peerIn{}
	b.slots = map[slotKey]*slot{}
}

// Receiver returns the sink the transport adapter offers received messages
// to.
func (r *Runner) Receiver() transport.Receiver { return &r.inbox }

func (b *inbox) peer(a types.Address) *peerIn {
	p := b.peers[a]
	if p == nil {
		p = &peerIn{}
		b.peers[a] = p
		b.order = append(b.order, a)
	}
	return p
}

// Offer implements transport.Receiver. It never blocks; it returns false
// when the peer's queue is full and the message was dropped.
func (b *inbox) Offer(in transport.Inbound) bool {
	r := b.r
	if !r.running.Load() {
		sync := r.d.Synchronising != nil && r.d.Synchronising()
		if transport.StoppedEngineAction(sync) == transport.FrameDisconnect {
			r.prefilter(in, nil, event.Disconnect, "engine_stopped")
			if r.d.Net != nil {
				r.d.Net.Disconnect(in.Peer, "consensus message while the engine is stopped")
			}
		} else {
			r.prefilter(in, nil, event.DropSilent, "engine_stopped")
		}
		return true
	}
	now := r.d.Clock.Mono()
	b.mu.Lock()
	p := b.peer(in.Peer)
	if len(p.q) >= r.cfg.InboxMessages || p.bytes+int64(len(in.Payload)) > r.cfg.InboxBytes {
		b.mu.Unlock()
		b.overflow(in.Peer, now)
		return false
	}
	b.mu.Unlock()
	// The key enters the known cache only for a message that was queued.
	if r.d.Transport != nil && r.d.Transport.SeenInbound(in.Peer, in.Code, in.Payload) {
		r.prefilter(in, nil, event.DropSilent, "duplicate")
		return true
	}
	b.mu.Lock()
	p.q = append(p.q, in)
	p.bytes += int64(len(in.Payload))
	b.cond.Signal()
	b.mu.Unlock()
	return true
}

// overflow counts a dropped message and disconnects the peer when it
// dropped more than the limit within the window, unless every attached
// peer's queue is full (then the node itself is slow).
func (b *inbox) overflow(a types.Address, now time.Duration) {
	r := b.r
	var attached []types.Address
	if r.d.Net != nil {
		for _, pi := range r.d.Net.Peers() {
			attached = append(attached, pi.Addr)
		}
	}
	b.mu.Lock()
	p := b.peer(a)
	p.drops = append(p.drops, now)
	for len(p.drops) > 0 && now-p.drops[0] > r.cfg.OverflowWindow {
		p.drops = p.drops[1:]
	}
	first := len(p.drops) == 1
	if len(attached) == 0 {
		attached = b.order
	}
	all := true
	for _, pa := range attached {
		x := b.peers[pa]
		if x == nil || len(x.q) < r.cfg.InboxMessages && x.bytes < r.cfg.InboxBytes/2 {
			all = false
			break
		}
	}
	disconnect := len(p.drops) > r.cfg.OverflowLimit && !all
	if disconnect {
		p.drops = nil
	}
	b.mu.Unlock()
	if first {
		r.emit(event.Record{Kind: event.Health, Fields: map[string]any{"what": "peer_inbound_overflow", "peer": hexAddr(a)}}, nil)
	}
	if disconnect {
		r.emit(event.Record{Kind: event.Health, Fields: map[string]any{"what": "peer_inbound_disconnect", "peer": hexAddr(a)}}, nil)
		if r.d.Net != nil {
			r.d.Net.Disconnect(a, "receive queue overflow")
		}
	}
}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// clear drops every queued message and slot.
func (b *inbox) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.peers { //wbft:unordered every peer is cleared
		p.q, p.bytes, p.ready = nil, 0, nil
	}
	b.slots = map[slotKey]*slot{}
}

// workerLoop runs receive checks until the runner closes.
func (r *Runner) workerLoop() {
	defer r.loopDone.Done()
	for {
		r.inbox.mu.Lock()
		for !r.inbox.queuedLocked() {
			select {
			case <-r.stopLoop:
				r.inbox.mu.Unlock()
				return
			default:
			}
			r.inbox.cond.Wait()
		}
		r.inbox.mu.Unlock()
		r.inbox.checkOne(false)
	}
}

func (b *inbox) queuedLocked() bool {
	for _, a := range b.order {
		if len(b.peers[a].q) > 0 {
			return true
		}
	}
	return false
}

// checkOne takes one queued message and checks it: from a random peer with
// input in manual mode, from the next peer in turn otherwise. It reports
// whether a message was taken.
func (b *inbox) checkOne(manual bool) bool {
	r := b.r
	b.mu.Lock()
	var cands []types.Address
	for _, a := range b.order {
		if len(b.peers[a].q) > 0 {
			cands = append(cands, a)
		}
	}
	if len(cands) == 0 {
		b.mu.Unlock()
		return false
	}
	var a types.Address
	if manual {
		a = cands[r.rand(len(cands))]
	} else {
		b.wIdx = (b.wIdx + 1) % len(cands)
		a = cands[b.wIdx]
	}
	p := b.peers[a]
	in := p.q[0]
	p.q = p.q[1:]
	p.bytes -= int64(len(in.Payload))
	b.mu.Unlock()
	b.check(in)
	return true
}

// check runs the receive checks on one message and puts it into its slot.
func (b *inbox) check(in transport.Inbound) {
	r := b.r
	snap := r.snap.Load()
	isMember := func(a types.Address, _ types.View) bool {
		if snap == nil || !snap.Running {
			return true
		}
		return (snap.Validators != nil && snap.Validators.Contains(a)) || (snap.PriorValidators != nil && snap.PriorValidators.Contains(a))
	}
	code := codec.Code(in.Code)
	v, err := consensus.Recover(code, in.Payload, isMember)
	if err != nil {
		reason := "signature"
		if errors.Is(err, ecdsa.ErrUnauthorizedAddress) {
			reason = "membership"
		}
		r.prefilter(in, nil, event.Ignore, reason)
		return
	}
	if snap != nil && snap.Running && outsideWindow(snap, code, v.Msg.View) {
		r.prefilter(in, v, event.Ignore, "window")
		return
	}
	digest, hasDigest := voteDigest(v.Msg)
	key := slotKey{src: v.Source, seq: v.Msg.View.Sequence.String(), round: v.Msg.View.Round.String(), code: code}
	dedup := codec.DedupKey(in.Payload)
	b.mu.Lock()
	if code == codec.CodePreprepare && v.Msg.View.Round.IsZero() {
		if first := b.slots[key]; first != nil && first.dedup != dedup {
			key.second = true
		}
	}
	s := b.slots[key]
	switch {
	case s == nil:
		holder := in.Peer
		if key.second {
			// The second round-0 PRE-PREPARE waits behind the first one.
			first := key
			first.second = false
			if f := b.slots[first]; f != nil {
				holder = f.ready
			}
		}
		b.slots[key] = &slot{in: in, dedup: dedup, digest: digest, sig: v.Msg.Signature, source: v.Source, ready: holder}
		p := b.peer(holder)
		p.ready = append(p.ready, key)
		b.mu.Unlock()
	case s.dedup == dedup:
		b.mu.Unlock()
		r.prefilter(in, v, event.DropSilent, "duplicate")
		return
	default:
		old := *s
		s.in, s.dedup, s.digest, s.sig = in, dedup, digest, v.Msg.Signature
		b.mu.Unlock()
		r.prefilter(old.in, nil, event.DropSilent, "overwritten")
		if hasDigest && old.digest != digest {
			kind := "equivocation"
			if code == codec.CodePreprepare && v.Msg.View.Round.IsZero() {
				kind = "round0_preprepare"
			}
			r.emit(event.Record{Kind: event.Evidence, View: event.ViewOf(v.Msg.View), Fields: map[string]any{
				"code": uint64(code), "source": hexAddr(v.Source), "digest_a": hexHash(old.digest), "digest_b": hexHash(digest),
				"sig_a": "0x" + hex.EncodeToString(old.sig), "sig_b": "0x" + hex.EncodeToString(v.Msg.Signature), "evidence_kind": kind}}, nil)
		}
	}
	r.wake()
}

// voteDigest returns what a message votes for: the digest of a PREPARE or
// COMMIT and the proposal of a PRE-PREPARE.
func voteDigest(m *codec.Message) (types.Hash, bool) {
	switch m.Code {
	case codec.CodePrepare, codec.CodeCommit:
		return m.Digest, true
	case codec.CodePreprepare:
		if m.Proposal != nil && m.Proposal.Header != nil {
			return codec.BlockHash(m.Proposal.Header), true
		}
	}
	return types.Hash{}, false
}

// outsideWindow reports a message that is TOO_FAR for the published view
// and for the first view of the next sequence (the snapshot may lag), or
// older than the previous sequence.
func outsideWindow(snap *consensus.Snapshot, code codec.Code, mv types.View) bool {
	if d, ok := snap.View.Sequence.Sub(mv.Sequence); ok && d.CmpUint64(1) > 0 {
		return true
	}
	if consensus.CheckMessage(snap.View, snap.State, snap.PriorRound, code, mv) != consensus.TooFar {
		return false
	}
	if mv.Sequence.Cmp(snap.View.Sequence) <= 0 {
		return true
	}
	next := types.View{Sequence: snap.View.Sequence.AddUint64(1)}
	return consensus.CheckMessage(next, consensus.AcceptRequest, types.Round{}, code, mv) == consensus.TooFar
}

// prefilter records a message that did not reach the core.
func (r *Runner) prefilter(in transport.Inbound, v *consensus.Verified, outcome event.OutcomeClass, reason string) {
	key := codec.DedupKey(in.Payload)
	f := map[string]any{"code": in.Code, "check": "prefilter", "outcome": outcome, "row": nil, "reason": reason,
		"via": "direct", "peer": hexAddr(in.Peer), "dedup_key": hexHash(key)}
	var view *event.View
	if v != nil {
		f["source"] = hexAddr(v.Source)
		view = event.ViewOf(v.Msg.View)
	}
	r.emit(event.Record{Kind: event.MsgOutcome, View: view, Fields: f}, nil)
	if r.d.Journal != nil {
		r.d.Journal.Put(journal.Record{Body: &journal.OutcomeRec{Code: in.Code, Peer: in.Peer, DedupKey: key, Outcome: outcome,
			Check: "prefilter", Row: -1, Reason: reason, Via: "direct"}})
	}
}

func (b *inbox) hasReady() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.order {
		if len(b.peers[a].ready) > 0 {
			return true
		}
	}
	return false
}

// take returns the next checked message, one per peer in turn.
func (b *inbox) take() (consensus.Message, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.order)
	for i := 0; i < n; i++ {
		b.cIdx = (b.cIdx + 1) % n
		p := b.peers[b.order[b.cIdx]]
		for len(p.ready) > 0 {
			k := p.ready[0]
			p.ready = p.ready[1:]
			s := b.slots[k]
			if s == nil {
				continue
			}
			delete(b.slots, k)
			return consensus.Message{Code: codec.Code(s.in.Code), Payload: s.in.Payload, Peer: s.in.Peer, RecvMono: s.in.RecvMono}, true
		}
	}
	return consensus.Message{}, false
}

// InboundBytes returns the payload bytes waiting in the per-peer receive
// queues (the wbft_peer_inbound_queue_bytes metric).
func (r *Runner) InboundBytes() int64 {
	b := &r.inbox
	b.mu.Lock()
	defer b.mu.Unlock()
	var n int64
	for _, p := range b.peers { //wbft:unordered a sum
		n += p.bytes
	}
	return n
}
