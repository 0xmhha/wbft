package sim

import (
	"math/rand/v2"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/transport"
	"github.com/0xmhha/wbft/types"
)

// syncInterval is how often a node that is behind asks a peer for blocks.
const syncInterval = 500 * time.Millisecond

// adapter is the fake transport of one node incarnation: every other live
// node is an attached peer; messages arrive after a delay drawn from the
// link's samples unless the link is cut or the message is lost.
type adapter struct {
	n   *node
	inc int
}

func newAdapter(n *node) *adapter { return &adapter{n: n, inc: n.inc} }

func (t *adapter) live() bool { return t.n.alive && t.n.inc == t.inc }

// linkOf returns the link from a to b.
func (s *simulation) linkOf(a, b types.Address) Link {
	for _, l := range s.sc.Links {
		if l.From == a && l.To == b {
			return l
		}
	}
	return s.sc.DefaultLink
}

// cut reports whether the link from a to b is cut now.
func (s *simulation) cut(a, b types.Address) bool {
	for _, p := range s.sc.Partitions {
		if s.l.now < p.From || s.l.now >= p.To {
			continue
		}
		for _, c := range p.Cut {
			if c[0] == a && c[1] == b || c[0] == b && c[1] == a {
				return true
			}
		}
	}
	return false
}

// deliverAfter schedules f on the link from a to b, unless the link is cut
// or the message is lost.
func (s *simulation) deliverAfter(a, b types.Address, f func()) bool {
	if s.cut(a, b) {
		return false
	}
	l := s.linkOf(a, b)
	if l.Loss > 0 && s.rng.Float64() < l.Loss {
		return false
	}
	d := sample(s.rng, l.Delay)
	s.l.after(d, func() {
		if !s.cut(a, b) {
			f()
		}
	})
	return true
}

// Send implements transport.Transport.
func (t *adapter) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	s := t.n.s
	res := make([]transport.SendResult, len(peers))
	for i, p := range peers {
		dst := s.byAddr[p]
		if dst == nil || !dst.alive || !t.live() {
			res[i] = transport.NotAttached
			continue
		}
		wires := []Wire{{Code: code, Payload: payload}}
		if adv := s.adversaryOf(t.n); adv != nil && adv.Rewrite != nil {
			wires = adv.Rewrite(s.advContext(t.n, adv), p, code, payload)
		}
		for _, w := range wires {
			t.sendOne(dst, w.Code, w.Payload)
		}
	}
	return res
}

func (t *adapter) sendOne(dst *node, code uint64, payload []byte) {
	s := t.n.s
	if t.n.jw != nil {
		t.n.jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: uint32(dst.i), Mono: s.l.now,
			WallNs: t.n.clock.Now().UnixNano(), Code: code, WireCode: code, Payload: payload,
			DedupKey: codec.DedupKey(payload), Cause: event.CauseBroadcast, Write: "ok"}})
	}
	from := t.n.v.address
	dinc := dst.inc
	s.deliverAfter(from, dst.v.address, func() {
		if !dst.alive || dst.inc != dinc || dst.r == nil {
			return
		}
		dst.receive(from, code, payload)
	})
}

// receive hands a message to the node's runner, as the transport's read
// loop does after the frame stage.
func (n *node) receive(from types.Address, code uint64, payload []byte) {
	s := n.s
	offer := "queued"
	data, deliver, act, _ := transport.DecodeFrame(code, payload)
	switch act {
	case transport.FrameDeliver:
		if !n.r.Receiver().Offer(transport.Inbound{Peer: from, Code: deliver, Payload: data, RecvMono: s.l.now}) {
			offer = "queue_full"
		}
	case transport.FrameDisconnect:
		offer = "frame_disconnect"
	default:
		offer = "frame_ignore"
	}
	if n.jw != nil {
		src := s.byAddr[from]
		idx := uint32(0)
		if src != nil {
			idx = uint32(src.i)
		}
		n.jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: idx, Mono: s.l.now, WallNs: n.clock.Now().UnixNano(),
			Code: code, WireCode: code, Payload: payload, DedupKey: codec.DedupKey(payload), Offer: offer}})
	}
}

// SetReceiver implements transport.Transport; the simulator calls the
// runner's receiver directly.
func (t *adapter) SetReceiver(transport.Receiver) {}

// PeerEvents implements transport.Transport.
func (t *adapter) PeerEvents() <-chan transport.PeerEvent { return nil }

// Peers implements transport.Transport: every other live node.
func (t *adapter) Peers() []transport.PeerInfo {
	var out []transport.PeerInfo
	for _, o := range t.n.s.nodes {
		if o != t.n && o.alive {
			out = append(out, transport.PeerInfo{Addr: o.v.address})
		}
	}
	return out
}

// Disconnect implements transport.Transport: the link to the peer is cut
// for a second in both directions.
func (t *adapter) Disconnect(peer types.Address, reason string) {
	s := t.n.s
	s.sc.Partitions = append(s.sc.Partitions, Partition{From: s.l.now, To: s.l.now + time.Second, Cut: [][2]types.Address{{t.n.v.address, peer}}})
	if t.n.ev != nil {
		_ = t.n.ev.Write(event.Record{Kind: event.Health, Fields: map[string]any{"what": "disconnect", "peer": hexAddr(peer), "reason": reason}}, t.n.stamp())
	}
}

// announce sends a stored block to the other nodes (block propagation).
func (t *adapter) announce(b *types.Block) {
	s := t.n.s
	for _, o := range s.nodes {
		if o == t.n {
			continue
		}
		o := o
		inc := o.inc
		s.deliverAfter(t.n.v.address, o.v.address, func() {
			if o.alive && o.inc == inc {
				_ = o.app.importBlock(b, "imported")
			}
		})
	}
}

// syncTick lets every node that is behind fetch blocks from the first peer
// in node order that has more.
func (s *simulation) syncTick() {
	for _, n := range s.nodes {
		if !n.alive {
			continue
		}
		for _, p := range s.nodes {
			if p == n || !p.alive || p.head() <= n.head() {
				continue
			}
			from, to := n.head()+1, p.head()
			n, p := n, p
			inc := n.inc
			var blocks []*types.Block
			for h := from; h <= to && h < from+64; h++ {
				blocks = append(blocks, p.app.chain.byNum[h])
			}
			s.deliverAfter(p.v.address, n.v.address, func() {
				if !n.alive || n.inc != inc {
					return
				}
				for _, b := range blocks {
					if err := n.app.importBlock(b, "synced"); err != nil {
						return
					}
				}
			})
			break
		}
	}
	s.l.after(syncInterval, s.syncTick)
}

// Wire is one message on the wire.
type Wire struct {
	Code    uint64
	Payload []byte
}

// Adversary replaces what a node sends. Rewrite is called for every
// message the node sends to one peer and returns the messages delivered
// instead (none for nil). Tick, if set, runs every Every between From and
// Until.
type Adversary struct {
	Node    types.Address
	Rewrite func(c *AdvContext, to types.Address, code uint64, payload []byte) []Wire
	Every   time.Duration
	From    time.Duration
	Until   time.Duration
	Tick    func(c *AdvContext)
}

// AdvContext is what an adversary may use.
type AdvContext struct {
	Now    time.Duration
	Secret []byte     // the node's secret key
	Rand   *rand.Rand // seeded by the scenario
	// Send delivers a message from the node to a peer over the link.
	Send func(to types.Address, code uint64, payload []byte)
	// Peers are the other nodes.
	Peers []types.Address
	// Head is the node's head and View its current view.
	Head types.Height
	View types.View
	// Block returns the node's stored block of a height, or nil.
	Block func(h uint64) *types.Block
}

func (s *simulation) adversaryOf(n *node) *Adversary {
	for i := range s.sc.Adversaries {
		if s.sc.Adversaries[i].Node == n.v.address {
			return &s.sc.Adversaries[i]
		}
	}
	return nil
}

func (s *simulation) advContext(n *node, a *Adversary) *AdvContext {
	c := &AdvContext{Now: s.l.now, Secret: n.v.ECDSA, Rand: s.rng, Head: n.app.chain.head.Header.Number,
		Block: func(h uint64) *types.Block { return n.app.chain.byNum[h] }}
	if n.r != nil {
		c.View = n.r.Snapshot().View
	}
	for _, o := range s.nodes {
		if o != n {
			c.Peers = append(c.Peers, o.v.address)
		}
	}
	c.Send = func(to types.Address, code uint64, payload []byte) {
		dst := s.byAddr[to]
		if dst == nil || !dst.alive || !n.alive || n.tr == nil {
			return
		}
		n.tr.sendOne(dst, code, payload)
	}
	return c
}

func (s *simulation) startAdversary(a Adversary) {
	if a.Tick == nil || a.Every <= 0 {
		return
	}
	n := s.byAddr[a.Node]
	var tick func()
	tick = func() {
		if a.Until > 0 && s.l.now >= a.Until {
			return
		}
		if n.alive {
			a.Tick(s.advContext(n, &a))
		}
		s.l.after(a.Every, tick)
	}
	s.l.at(a.From, tick)
}
