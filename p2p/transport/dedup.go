// Copyright 2017 The go-ethereum Authors
// Copyright 2024 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// The caches and the choice of gossip targets follow HandleMsg, Broadcast and
// Gossip of consensus/wbft/backend of go-stablenet (commit 740526d03), which
// are derived from quorum/consensus/istanbul/backend.

package transport

import (
	"bytes"
	"errors"
	"slices"
	"sync"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// Cache sizes of the reference.
const (
	// InmemoryPeers is the number of peer addresses in the recent cache.
	InmemoryPeers = 40
	// InmemoryMessages is the number of keys per peer and in the known cache.
	InmemoryMessages = 1024
)

// DedupOptions configure a Dedup.
type DedupOptions struct {
	// Self is the node's address; it is never a gossip target.
	Self types.Address

	// The fields below are reserved for optional behaviours of a later
	// milestone and must be left at their zero values.

	// KeyWithCode puts the message code into the cache key.
	KeyWithCode bool
	// RecordAfterSend records a key for a peer only after a successful send.
	RecordAfterSend bool
	// Observers are non-validator peers that also receive gossip.
	Observers []types.Address
}

// ErrReservedOption is returned by NewDedup for a reserved option that is
// set.
var ErrReservedOption = errors.New("transport: dedup option is not available")

// Dedup wraps a Transport with the two caches of the reference: the recent
// cache of message keys per peer address (InmemoryPeers addresses of
// InmemoryMessages keys) and the known cache of InmemoryMessages keys. The
// key of a payload is codec.DedupKey (the code is not part of it). Dedup is
// safe for concurrent use.
//
// Spec: WBFT-NET-022
type Dedup struct {
	mu     sync.Mutex
	t      Transport
	opt    DedupOptions
	recent *lru[types.Address, *lru[types.Hash, struct{}]]
	known  *lru[types.Hash, struct{}]
}

// NewDedup returns a Dedup over t.
func NewDedup(t Transport, opt DedupOptions) (*Dedup, error) {
	if opt.KeyWithCode || opt.RecordAfterSend || len(opt.Observers) > 0 {
		return nil, ErrReservedOption
	}
	return &Dedup{
		t:      t,
		opt:    opt,
		recent: newLRU[types.Address, *lru[types.Hash, struct{}]](InmemoryPeers),
		known:  newLRU[types.Hash, struct{}](InmemoryMessages),
	}, nil
}

// peerCache returns the recent cache of peer, creating it if needed; the
// returned cache is refreshed in the peer LRU when created.
func (d *Dedup) peerCache(peer types.Address) *lru[types.Hash, struct{}] {
	m, ok := d.recent.Get(peer)
	if !ok {
		m = newLRU[types.Hash, struct{}](InmemoryMessages)
		d.recent.Add(peer, m)
	}
	return m
}

// SeenInbound records a message received from peer: its key goes into the
// recent cache of peer first, then the known cache is checked. It reports
// whether the key was already known (the message is then dropped); an unknown
// key is added to the known cache before the core checks the message.
//
// Spec: WBFT-NET-023, WBFT-NET-024
func (d *Dedup) SeenInbound(peer types.Address, code uint64, payload []byte) (dup bool) {
	_ = code // the reference key has no code
	key := codec.DedupKey(payload)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.peerCache(peer).Add(key, struct{}{})
	if _, ok := d.known.Get(key); ok {
		return true
	}
	d.known.Add(key, struct{}{})
	return false
}

// Broadcast sends an own message to the validators of vs: nothing when the
// node is not a member of vs, otherwise Gossip. The self-delivery is the
// caller's.
//
// Spec: WBFT-NET-030
func (d *Dedup) Broadcast(vs *validator.Set, code uint64, payload []byte, cause event.SendCause) []types.Address {
	if vs == nil || !vs.Contains(d.opt.Self) {
		return nil
	}
	return d.Gossip(vs, code, payload, cause)
}

// Gossip adds the key of payload to the known cache and sends payload to the
// attached peers that are members of vs other than the node itself, skipping
// every peer whose recent cache holds the key. The key is recorded for a
// peer before the send, whatever its result. It returns the peers sent to in
// address order. A code outside 0x12 .. 0x15 goes out under 0x11.
//
// Spec: WBFT-NET-031, WBFT-NET-032, WBFT-SM-011
func (d *Dedup) Gossip(vs *validator.Set, code uint64, payload []byte, cause event.SendCause) []types.Address {
	_ = cause
	key := codec.DedupKey(payload)
	d.mu.Lock()
	d.known.Add(key, struct{}{})
	var targets []types.Address
	if vs != nil {
		var candidates []types.Address
		for _, pi := range d.t.Peers() {
			a := pi.Addr
			if a != d.opt.Self && vs.Contains(a) && !slices.Contains(candidates, a) {
				candidates = append(candidates, a)
			}
		}
		slices.SortStableFunc(candidates, func(a, b types.Address) int { return bytes.Compare(a[:], b[:]) })
		for _, a := range candidates {
			m, ok := d.recent.Get(a)
			if ok {
				if _, seen := m.Get(key); seen {
					continue
				}
			} else {
				m = newLRU[types.Hash, struct{}](InmemoryMessages)
			}
			m.Add(key, struct{}{})
			d.recent.Add(a, m)
			targets = append(targets, a)
		}
	}
	d.mu.Unlock()
	if len(targets) > 0 {
		out := code
		if code < CodeFirst || code > CodeLast {
			out = CodeLegacy
		}
		d.t.Send(targets, out, payload)
	}
	return targets
}

// Known reports whether the key of payload is in the known cache, without
// refreshing it.
func (d *Dedup) Known(payload []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.known.Contains(codec.DedupKey(payload))
}

// SentOrReceived reports whether the key of payload is in the recent cache of
// peer, without refreshing it.
func (d *Dedup) SentOrReceived(peer types.Address, payload []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, ok := d.recent.items[peer]
	if !ok {
		return false
	}
	return m.Value.(*lruEntry[types.Address, *lru[types.Hash, struct{}]]).val.Contains(codec.DedupKey(payload))
}
