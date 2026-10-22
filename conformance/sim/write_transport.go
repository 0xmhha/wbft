package sim

import (
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/writequeue"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// WriteQueueProfile explicitly separates simulated local writes and ordinary
// link delivery. It does not model socket I/O or select completed-write caches.
type WriteQueueProfile struct {
	Waiting   int
	WriteTime time.Duration
}

func cloneWriteQueue(p *WriteQueueProfile, sc Scenario) (*WriteQueueProfile, error) {
	if p == nil {
		return nil, nil
	}
	if p.Waiting < 1 || p.Waiting > 65536 || p.WriteTime < 0 || p.WriteTime > sc.Until.Duration {
		return nil, fmt.Errorf("%w: invalid write queue capacity or service", ErrScenario)
	}
	// This new model accepts normal lifecycles only. It must not silently route
	// adversary, frame selection or fault paths through the legacy transport.
	if len(sc.Adversaries)+len(sc.Faults)+len(sc.Disk)+len(sc.Partitions)+len(sc.MessageChanges) != 0 || sc.DefaultLink.Loss != 0 {
		return nil, fmt.Errorf("%w: write queue requires normal transport and lifecycles", ErrScenario)
	}
	for _, l := range sc.Links {
		if l.Loss != 0 {
			return nil, fmt.Errorf("%w: write queue requires lossless links", ErrScenario)
		}
	}
	for _, ev := range sc.Schedule {
		if ev.Action != ActionStop && ev.Action != ActionRestart && ev.Action != ActionEngineStop && ev.Action != ActionEngineStart {
			return nil, fmt.Errorf("%w: write queue requires normal lifecycle actions", ErrScenario)
		}
	}
	out := *p
	return &out, nil
}

type writeRoute struct {
	inc    int
	q      *writequeue.Queue
	target transport.WritePeer
	remote *writeRoute
	source *cacheSources
}

// Only this explicit adapter implements WriteSender; default adapter method
// sets and the legacy simulator's immediate-write bytes remain unchanged.
type writeAdapter struct {
	*adapter
	routes   map[*node]*writeRoute
	blocked  map[*node]time.Duration
	closed   bool
	receiver transport.Receiver
}

var _ transport.WriteSender = (*writeAdapter)(nil)

func (t *writeAdapter) route(dst *node) *writeRoute {
	if t.closed || !t.live() || dst == nil || !dst.alive || dst == t.n || t.blocked[dst] > t.n.s.l.c.Mono() {
		return nil
	}
	if dst.writes != nil && (dst.writes.closed || dst.writes.blocked[t.n] > t.n.s.l.c.Mono()) {
		return nil
	}
	if r := t.routes[dst]; r != nil {
		if r.inc == dst.inc {
			return r
		}
		r.q.Close()
	}
	s, inc := t.n.s, dst.inc
	p := t.n.spec.WriteQueue
	var original *writeRoute
	q, err := writequeue.New(&s.l.c, dst.v.address, writequeue.Options{Waiting: p.Waiting, WriteTime: p.WriteTime}, func(code uint64, payload []byte) {
		if !t.live() || !dst.alive || dst.inc != inc {
			return
		}
		remote := original.remote
		s.deliverAfter(t.n.v.address, dst.v.address, func() {
			if t.live() && dst.alive && dst.inc == inc && dst.r != nil && t.routes[dst] == original && len(original.q.WritePeers()) != 0 {
				var stream *transport.WriteSession
				if remote != nil {
					if dst.writes == nil || dst.writes.routes[t.n] != remote || !remote.target.Session.Active() {
						return
					}
					stream = remote.target.Session
				}
				// Scenario validation excludes delivery selectors for this model.
				dst.receiveFromStream(t.n.v.address, code, payload, stream)
			}
		})
	})
	if err != nil {
		panic(err) // scenario validation established constructor preconditions
	}
	original = &writeRoute{inc: inc, q: q, target: q.WritePeers()[0], source: t.n.sources}
	t.routes[dst] = original
	if original.source != nil {
		original.source.session(original.target, journal.SessionObserved)
	}
	if dst.writes != nil {
		if remote := dst.writes.route(t.n); remote != nil {
			original.remote, remote.remote = remote, original
		}
	}
	return original
}

func (t *writeAdapter) WritePeers() []transport.WritePeer {
	var out []transport.WritePeer
	for _, dst := range t.n.s.nodes {
		if r := t.route(dst); r != nil {
			out = append(out, r.q.WritePeers()...)
		}
	}
	return out
}

func (t *writeAdapter) SendWrite(target transport.WritePeer, code uint64, payload []byte, attempt transport.SendAttempt, done func(transport.WriteReceipt)) transport.SendResult {
	r := t.route(t.n.s.byAddr[target.Addr])
	if r == nil || done == nil {
		return transport.NotAttached
	}
	// The queue owns its own copy. The journal callback must also retain the
	// original bytes, independent of the caller's next buffer use.
	owned := append([]byte(nil), payload...)
	source := r.source
	return r.q.SendWrite(target, code, owned, attempt, func(receipt transport.WriteReceipt) {
		if receipt.Result == transport.LocalWriteOK && source != nil {
			source.wrote(target, code, owned, attempt)
		} else if receipt.Result == transport.LocalWriteOK && t.n.jw != nil {
			dst := t.n.s.byAddr[target.Addr]
			t.n.jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: uint32(dst.i), Mono: t.n.s.l.c.Mono(),
				WallNs: t.n.clock.Now().UnixNano(), Code: code, WireCode: code, Payload: owned,
				DedupKey: codec.DedupKey(owned), Cause: event.CauseBroadcast, Write: "ok"}})
		}
		done(receipt)
	})
}

func (t *writeAdapter) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	out := make([]transport.SendResult, len(peers))
	for i, peer := range peers {
		out[i] = transport.NotAttached
		if r := t.route(t.n.s.byAddr[peer]); r != nil {
			if targets := r.q.WritePeers(); len(targets) != 0 {
				out[i] = t.SendWrite(targets[0], code, payload, transport.SendAttempt{}, func(transport.WriteReceipt) {})
			}
		}
	}
	return out
}

func (t *writeAdapter) closePeer(dst *node) {
	if r := t.routes[dst]; r != nil {
		delete(t.routes, dst)
		remote := r.remote
		r.remote = nil
		if remote != nil {
			remote.remote = nil
			if dst.writes != nil && dst.writes.routes[t.n] == remote {
				delete(dst.writes.routes, t.n)
			}
		}
		// Remove both original routes before callbacks may reconnect.
		r.q.Close()
		if r.source != nil {
			r.source.session(r.target, string(transport.SessionRemoved))
		}
		if remote != nil {
			remote.q.Close()
			if remote.source != nil {
				remote.source.session(remote.target, string(transport.SessionRemoved))
			}
		}
	}
}

func (t *writeAdapter) SetReceiver(r transport.Receiver) { t.receiver = r }

func (t *writeAdapter) Peers() []transport.PeerInfo {
	var out []transport.PeerInfo
	for _, p := range t.WritePeers() {
		out = append(out, transport.PeerInfo{Addr: p.Addr})
	}
	return out
}

// Disconnect ends original queues using the existing one-second reconnect
// delay, without introducing partition mutations into this normal-only model.
func (t *writeAdapter) Disconnect(peer types.Address, _ string) {
	dst := t.n.s.byAddr[peer]
	if dst == nil {
		return
	}
	until := time.Duration(math.MaxInt64)
	if t.n.s.l.c.Mono() <= until-time.Second {
		until = t.n.s.l.c.Mono() + time.Second
	}
	block := func(a *writeAdapter, other *node) {
		if a.blocked == nil {
			a.blocked = map[*node]time.Duration{}
		}
		a.blocked[other] = until
		a.closePeer(other)
	}
	block(t, dst)
	if dst.writes != nil {
		block(dst.writes, t.n)
	}
}

func (n *node) closeWriteQueues() {
	if n.writes != nil {
		n.writes.closed = true
	}
	// Node order fixes terminal callback order without ranging over maps.
	for _, other := range n.s.nodes {
		if n.writes != nil {
			n.writes.closePeer(other)
		}
		if other.writes != nil && other != n {
			other.writes.closePeer(n)
		}
	}
}
