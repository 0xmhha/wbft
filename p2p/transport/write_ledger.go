package transport

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// WriteLedgerOptions bound outstanding local requests, independently of the
// observer. These entry counts do not bound transport payloads or process heap.
type WriteLedgerOptions struct {
	Pending, PerPeer uint64
	KeyWithCode      bool
}

// WriteDecision separates a completed recent entry from pending work and from
// a local capacity refusal. Pending work is never a successful recent entry.
type WriteDecision uint8

const (
	WriteReserved WriteDecision = iota + 1
	WriteAlreadyRecent
	WriteAlreadyPending
	WritePendingFull
	WriteUnavailable
)

type writeKey struct {
	code    uint64
	payload types.Hash
}

type pendingWriteKey struct {
	target WritePeer
	key    writeKey
}

type writeReservation struct {
	owner   *WriteLedger
	target  WritePeer
	key     writeKey
	code    uint64
	payload types.Hash
}

// WriteTicket is one ledger-owned request. Its zero value owns nothing. A
// callback closes over this ticket; no recorder identity is used or serialized.
type WriteTicket struct{ reservation *writeReservation }

// WriteLedger retains recent entries only after a successful actual local
// write. Completed address-cache entries survive reconnection; outstanding
// requests from an ended stream cannot register a new entry in any stream.
// Methods never call the transport or an observer while holding the mutex.
// This type is a functional primitive, not an enabled node cache policy.
type WriteLedger struct {
	mu      sync.Mutex
	opt     WriteLedgerOptions
	closed  bool
	pending map[pendingWriteKey]*writeReservation
	counts  map[types.Address]uint64
	recent  *lru[types.Address, *lru[writeKey, struct{}]]
}

// NewWriteLedger requires explicit positive pending entry limits. It uses the
// existing address/recent capacities; it does not select an operating budget.
func NewWriteLedger(opt WriteLedgerOptions) (*WriteLedger, error) {
	if opt.Pending == 0 || opt.PerPeer == 0 || opt.PerPeer > opt.Pending {
		return nil, errors.New("transport: write ledger requires positive pending and per-peer limits")
	}
	return &WriteLedger{opt: opt, pending: make(map[pendingWriteKey]*writeReservation), counts: make(map[types.Address]uint64), recent: newLRU[types.Address, *lru[writeKey, struct{}]](InmemoryPeers)}, nil
}

func (l *WriteLedger) key(code uint64, payload []byte) writeKey {
	key := writeKey{payload: codec.DedupKey(payload)}
	if l.opt.KeyWithCode {
		key.code = code
	}
	return key
}

func (l *WriteLedger) release(r *writeReservation) {
	delete(l.pending, pendingWriteKey{target: r.target, key: r.key})
	if l.counts[r.target.Addr] <= 1 {
		delete(l.counts, r.target.Addr)
	} else {
		l.counts[r.target.Addr]--
	}
}

func (l *WriteLedger) pruneClosed() {
	for _, r := range l.pending { //wbft:unordered every closed stream is reclaimed
		if !r.target.Session.Active() {
			l.release(r)
		}
	}
}

// Prepare reserves functional ownership before calling SendWrite. Callers must
// distinguish the decision when no ticket is returned; capacity refusal and
// pending suppression are not evidence that a message was written.
func (l *WriteLedger) Prepare(target WritePeer, code uint64, payload []byte) (WriteTicket, WriteDecision) {
	if !target.Session.Active() || CheckOutbound(code, payload) != nil {
		return WriteTicket{}, WriteUnavailable
	}
	key := l.key(code, payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !target.Session.Active() {
		return WriteTicket{}, WriteUnavailable
	}
	l.pruneClosed()
	if recent, ok := l.recent.Get(target.Addr); ok {
		if _, exists := recent.Get(key); exists {
			return WriteTicket{}, WriteAlreadyRecent
		}
	}
	pk := pendingWriteKey{target: target, key: key}
	if l.pending[pk] != nil {
		return WriteTicket{}, WriteAlreadyPending
	}
	if uint64(len(l.pending)) >= l.opt.Pending || l.counts[target.Addr] >= l.opt.PerPeer {
		return WriteTicket{}, WritePendingFull
	}
	r := &writeReservation{owner: l, target: target, key: key, code: code, payload: sha256.Sum256(payload)}
	l.pending[pk] = r
	l.counts[target.Addr]++
	return WriteTicket{reservation: r}, WriteReserved
}

func (l *WriteLedger) owns(ticket WriteTicket) *writeReservation {
	r := ticket.reservation
	if r == nil || r.owner != l || l.pending[pendingWriteKey{target: r.target, key: r.key}] != r {
		return nil
	}
	return r
}

// QueueResult reclaims a rejected queue request. A Queued return never revives
// ownership that a synchronous completion or stream close already consumed.
func (l *WriteLedger) QueueResult(ticket WriteTicket, result SendResult) {
	if result == Queued {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.owns(ticket); r != nil {
		l.release(r)
	}
}

// Complete accepts only the exact ticket, stream, code and queued bytes. It
// returns true only when this completion adds a successful recent entry.
func (l *WriteLedger) Complete(ticket WriteTicket, receipt WriteReceipt) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.owns(ticket)
	if r == nil || receipt.Target != r.target || receipt.Code != r.code || receipt.PayloadSHA256 != r.payload {
		return false
	}
	if receipt.Result != LocalWriteOK && receipt.Result != LocalWriteCancelled && receipt.Result != LocalWriteError {
		return false
	}
	l.release(r)
	if l.closed || receipt.Result != LocalWriteOK || !r.target.Session.Active() {
		return false
	}
	m, ok := l.recent.Get(r.target.Addr)
	if !ok {
		m = newLRU[writeKey, struct{}](InmemoryMessages)
		l.recent.Add(r.target.Addr, m)
	}
	m.Add(r.key, struct{}{})
	return true
}

// Recent inspects completed entries without changing their LRU order.
func (l *WriteLedger) Recent(peer types.Address, code uint64, payload []byte) bool {
	key := l.key(code, payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.recent.items[peer]
	return ok && entry.Value.(*lruEntry[types.Address, *lru[writeKey, struct{}]]).val.Contains(key)
}

// Pending counts owned outstanding requests after reclaiming ended streams.
// It accounts for ledger records, not payload bytes still owned by an adapter.
func (l *WriteLedger) Pending() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneClosed()
	return uint64(len(l.pending))
}

// Close ends this ledger lifetime without closing transport-owned sessions.
// Old callbacks can never transfer ownership into a replacement ledger.
func (l *WriteLedger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	clear(l.pending)
	clear(l.counts)
	l.recent = newLRU[types.Address, *lru[writeKey, struct{}]](InmemoryPeers)
}
