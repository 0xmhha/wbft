package transport

import (
	"crypto/sha256"
	"errors"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"sync"
)

// ValidationScope is one immutable authority/checking context owned by the
// receiver. It has an independent lifetime from a peer stream or recorder.
// The receiver closes it when that validation context is replaced.
type ValidationScope struct{ lifetime *WriteSession }

func NewValidationScope() *ValidationScope {
	return &ValidationScope{lifetime: NewWriteSession()}
}

func (s *ValidationScope) Active() bool { return s != nil && s.lifetime.Active() }
func (s *ValidationScope) Close() {
	if s != nil {
		s.lifetime.Close()
	}
}

// ReceiveOrigin is optional frozen capture provenance. It never grants cache
// ownership or validator authority and is not a clock conversion.
type ReceiveOrigin struct {
	WriterRun string
	CaptureID uint64
}

type ReceiveLedgerOptions struct {
	Pending, PerPeer uint64
	KeyWithCode      bool
}

type ReceiveDecision uint8

const (
	ReceiveReserved ReceiveDecision = iota + 1
	ReceiveKnown
	ReceivePendingFull
	ReceiveUnavailable
	ReceiveRegistered
	ReceiveDuplicate
	ReceiveExpired
)

type receiveKey struct {
	scope *ValidationScope
	key   writeKey
}

type receiveReservation struct {
	owner   *ReceiveLedger
	scope   *ValidationScope
	peer    types.Address
	code    uint64
	key     receiveKey
	payload types.Hash
	origin  ReceiveOrigin
}

// ReceiveTicket owns one check, rather than one payload key. Two normal
// transports of a still-unverified message may own independent checks.
type ReceiveTicket struct{ reservation *receiveReservation }

func (t ReceiveTicket) Origin() ReceiveOrigin {
	if t.reservation == nil {
		return ReceiveOrigin{}
	}
	return t.reservation.origin
}

// ReceiveLedger separates pending checks from verified known/recent entries.
// It does not perform authentication: Accept is called only after the receiver
// fully checks signatures, membership and its view window in ticket's scope.
// This primitive does not enable a node policy or change the legacy Dedup.
type ReceiveLedger struct {
	mu      sync.Mutex
	opt     ReceiveLedgerOptions
	closed  bool
	pending map[*receiveReservation]struct{}
	counts  map[types.Address]uint64
	known   *lru[receiveKey, struct{}]
	recent  *lru[types.Address, *lru[receiveKey, struct{}]]
}

func NewReceiveLedger(opt ReceiveLedgerOptions) (*ReceiveLedger, error) {
	if opt.Pending == 0 || opt.PerPeer == 0 || opt.PerPeer > opt.Pending {
		return nil, errors.New("transport: receive ledger requires positive pending and per-peer limits")
	}
	return &ReceiveLedger{opt: opt, pending: make(map[*receiveReservation]struct{}), counts: make(map[types.Address]uint64), known: newLRU[receiveKey, struct{}](InmemoryMessages), recent: newLRU[types.Address, *lru[receiveKey, struct{}]](InmemoryPeers)}, nil
}

func (l *ReceiveLedger) key(scope *ValidationScope, code uint64, payload []byte) receiveKey {
	// Use the same explicit tuple policy as the write ledger. The original
	// payload-only frame key remains unchanged in every journal and message.
	key := writeKey{payload: codec.DedupKey(payload)}
	if l.opt.KeyWithCode {
		key.code = code
	}
	return receiveKey{scope: scope, key: key}
}

func (l *ReceiveLedger) release(r *receiveReservation) {
	delete(l.pending, r)
	if l.counts[r.peer] <= 1 {
		delete(l.counts, r.peer)
	} else {
		l.counts[r.peer]--
	}
}

func (l *ReceiveLedger) pruneClosed() {
	for r := range l.pending { //wbft:unordered every closed checking context is reclaimed
		if !r.scope.Active() {
			l.release(r)
		}
	}
}

// Prepare owns a pending check without registering unverified bytes. It does
// not suppress another pending copy. Origin is retained only when complete and
// consistent with the adapter capture; unavailable metadata never rejects an
// otherwise valid functional check.
func (l *ReceiveLedger) Prepare(scope *ValidationScope, in Inbound, origin ReceiveOrigin) (ReceiveTicket, ReceiveDecision) {
	if !scope.Active() {
		return ReceiveTicket{}, ReceiveUnavailable
	}
	key := l.key(scope, in.Code, in.Payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !scope.Active() {
		return ReceiveTicket{}, ReceiveUnavailable
	}
	l.pruneClosed()
	if l.known.Contains(key) {
		return ReceiveTicket{}, ReceiveKnown
	}
	if uint64(len(l.pending)) >= l.opt.Pending || l.counts[in.Peer] >= l.opt.PerPeer {
		return ReceiveTicket{}, ReceivePendingFull
	}
	if origin.WriterRun == "" || origin.CaptureID == 0 || origin.CaptureID != in.Capture {
		origin = ReceiveOrigin{}
	}
	r := &receiveReservation{owner: l, scope: scope, peer: in.Peer, code: in.Code, key: key, payload: sha256.Sum256(in.Payload), origin: origin}
	l.pending[r] = struct{}{}
	l.counts[in.Peer]++
	return ReceiveTicket{reservation: r}, ReceiveReserved
}

func (l *ReceiveLedger) owns(ticket ReceiveTicket) *receiveReservation {
	r := ticket.reservation
	if r == nil || r.owner != l {
		return nil
	}
	if _, ok := l.pending[r]; !ok {
		return nil
	}
	return r
}

// Accept commits a completed full check in its original scope. A stale worker
// cannot authenticate for a replacement scope. The capture reference remains
// available through ticket even after this terminal transition.
func (l *ReceiveLedger) Accept(ticket ReceiveTicket, in Inbound) ReceiveDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.owns(ticket)
	if r == nil {
		return ReceiveUnavailable
	}
	if in.Peer != r.peer || in.Code != r.code || sha256.Sum256(in.Payload) != r.payload {
		return ReceiveUnavailable
	}
	l.release(r)
	if l.closed || !r.scope.Active() {
		return ReceiveExpired
	}
	_, known := l.known.Get(r.key)
	if !known {
		l.known.Add(r.key, struct{}{})
	}
	m, ok := l.recent.Get(r.peer)
	if !ok {
		m = newLRU[receiveKey, struct{}](InmemoryMessages)
		l.recent.Add(r.peer, m)
	}
	m.Add(r.key, struct{}{})
	if known {
		return ReceiveDuplicate
	}
	return ReceiveRegistered
}

// Cancel releases a failed or abandoned check without registering its key.
func (l *ReceiveLedger) Cancel(ticket ReceiveTicket) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.owns(ticket); r != nil {
		l.release(r)
	}
}

func (l *ReceiveLedger) Known(scope *ValidationScope, code uint64, payload []byte) bool {
	if !scope.Active() {
		return false
	}
	key := l.key(scope, code, payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.known.Contains(key)
}

func (l *ReceiveLedger) Pending() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneClosed()
	return uint64(len(l.pending))
}

// Recent inspects only verified reception in the requested checking context.
func (l *ReceiveLedger) Recent(scope *ValidationScope, peer types.Address, code uint64, payload []byte) bool {
	if !scope.Active() {
		return false
	}
	key := l.key(scope, code, payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.recent.items[peer]
	return ok && entry.Value.(*lruEntry[types.Address, *lru[receiveKey, struct{}]]).val.Contains(key)
}

func (l *ReceiveLedger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	clear(l.pending)
	clear(l.counts)
	l.known = newLRU[receiveKey, struct{}](InmemoryMessages)
	l.recent = newLRU[types.Address, *lru[receiveKey, struct{}]](InmemoryPeers)
}
