package transport

import (
	"bytes"
	"encoding/binary"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"reflect"
	"testing"
)

type cacheProbeTransport struct {
	fakeTransport
	next uint64
	ops  []CacheOperation
}

func (p *cacheProbeTransport) BeginCache(types.Address) uint64  { p.next++; return p.next }
func (p *cacheProbeTransport) CacheOperation(op CacheOperation) { p.ops = append(p.ops, op) }

func TestCacheObserverPreservesOperationsAndLRUEviction(t *testing.T) {
	self, p1, p2 := addr(0), addr(1), addr(2)
	tr := &cacheProbeTransport{fakeTransport: fakeTransport{peers: []types.Address{p2, p1, p1, self, addr(9)}}}
	d := newDedup(t, tr, self)
	vs := set(t, self, p1, p2)
	payload := []byte{0xc0}
	d.SeenInbound(p1, 0x13, payload)
	before := len(tr.ops)
	if !d.Known(payload) || !d.SentOrReceived(p1, payload) || len(tr.ops) != before {
		t.Fatal("read-only query became a mutation")
	}
	got := d.GossipTargets(vs, 0x13, payload, event.CauseRelay)
	if !reflect.DeepEqual(got.Targets, []types.Address{p2}) || !reflect.DeepEqual(got.Suppressed, []types.Address{p1}) {
		t.Fatal(got)
	}
	for i, op := range tr.ops {
		if op.Instance != 1 || op.Sequence != uint64(i+1) || op.PayloadSHA256 != payloadSHA256(payload) {
			t.Fatal("operation identity lost", op)
		}
	}
	if tr.ops[0].Known || tr.ops[0].Recent || !tr.ops[1].Known || len(tr.ops[1].Candidates) != 2 {
		t.Fatal("cache preconditions changed", tr.ops)
	}
	// Known and per-peer caches evict the oldest key after exactly 1024 others.
	for i := range InmemoryMessages {
		b := binary.BigEndian.AppendUint64([]byte{0xaa}, uint64(i))
		d.SeenInbound(p1, 0x13, b)
	}
	if d.Known(payload) || d.SentOrReceived(p1, payload) {
		t.Fatal("message LRU eviction changed")
	}
	// A fresh cache instance must not reuse this instance's sequence domain.
	other := newDedup(t, tr, self)
	other.GossipTargets(nil, 0x13, payload, event.CauseRetry)
	last := tr.ops[len(tr.ops)-1]
	if last.Instance != 2 || last.Sequence != 1 || last.Available || len(last.Targets) != 0 {
		t.Fatal("instance boundary lost", last)
	}
}

func TestCacheObservationDoesNotChangeTargetsOrPayloads(t *testing.T) {
	self, p1, p2 := addr(0), addr(1), addr(2)
	plain := &fakeTransport{peers: []types.Address{p1, p2}}
	observed := &cacheProbeTransport{fakeTransport: fakeTransport{peers: []types.Address{p1, p2}}}
	off, on := newDedup(t, plain, self), newDedup(t, observed, self)
	vs := set(t, self, p1, p2)
	for i := range 50 {
		payload := []byte{0xc1, byte(i % 7)}
		frozen := bytes.Clone(payload)
		if i%3 == 0 {
			if off.SeenInbound(p1, 0x13, payload) != on.SeenInbound(p1, 0x13, payload) {
				t.Fatal("known result changed")
			}
		}
		a, b := off.GossipTargets(vs, 0x13, payload, event.CauseRetry), on.GossipTargets(vs, 0x13, payload, event.CauseRetry)
		if !reflect.DeepEqual(a, b) || !bytes.Equal(payload, frozen) {
			t.Fatal("observation changed gossip", a, b)
		}
	}
	if !reflect.DeepEqual(plain.sends, observed.sends) {
		t.Fatal("actual send list changed")
	}
}
