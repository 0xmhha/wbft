// Package devnet is a small TCP transport for development networks and
// tests. It carries the consensus messages of transport.Transport and an
// application channel (for example blocks for a node that fell behind)
// between nodes whose addresses and network endpoints are listed in the
// configuration.
//
// It is not for production networks: a peer is identified by the address it
// claims in its hello message, and connections are neither authenticated
// nor encrypted. Consensus messages are signed, so a false identity cannot
// forge votes, but it can take a peer's place in the connection table.
// Production nodes use the transport adapter of their application.
package devnet

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Peer is one node of the network.
type Peer struct {
	Addr     types.Address
	Endpoint string // host:port
}

// Config configures a Transport.
type Config struct {
	// Self is the address of this node.
	Self types.Address
	// Listen is the endpoint to accept connections on (host:port; port 0
	// picks a free port).
	Listen string
	// Network names the network; peers with another name are refused.
	Network string
	// Peers are the other nodes. A node dials the peers whose address is
	// greater than its own and accepts the others, so each pair has one
	// connection.
	Peers []Peer
	// QueueSize bounds the send queue of a peer (default 1024 messages).
	QueueSize int
	// RedialInterval is the pause between dial attempts (default 500 ms).
	RedialInterval time.Duration
	// Logger logs; nil discards.
	Logger *slog.Logger
}

// Channels of a frame.
const (
	chanConsensus byte = 0
	chanApp       byte = 1
)

// helloMagic starts the hello message of a connection.
const helloMagic = "wbft-devnet/1"

// maxFrame bounds the payload of a received frame.
const maxFrame = transport.MaxFramePayload + 1024

// AppHandler receives the messages of the application channel from the
// read loop of a peer; it must not block.
type AppHandler func(peer types.Address, code uint64, payload []byte)

// Transport is a development transport. It implements transport.Transport.
type Transport struct {
	cfg   Config
	log   *slog.Logger
	start time.Time

	mu     sync.Mutex
	ln     net.Listener
	peers  map[types.Address]*conn
	recv   transport.Receiver
	obs    transport.FrameObserver
	app    AppHandler
	closed bool

	events chan transport.PeerEvent
	done   chan struct{}
	wg     sync.WaitGroup
}

var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Observed  = (*Transport)(nil)
)

// conn is the connection of one peer.
type conn struct {
	peer  types.Address
	c     net.Conn
	out   chan frame
	since time.Time
	once  sync.Once
	gone  chan struct{}
}

type frame struct {
	ch      byte
	code    uint64
	payload []byte
}

// New returns a transport that is not started.
func New(cfg Config) (*Transport, error) {
	if cfg.Listen == "" {
		return nil, errors.New("devnet: Listen is required")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.RedialInterval <= 0 {
		cfg.RedialInterval = 500 * time.Millisecond
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Transport{cfg: cfg, log: log, start: time.Now(), peers: map[types.Address]*conn{},
		events: make(chan transport.PeerEvent, 256), done: make(chan struct{})}, nil
}

// Listen opens the listening endpoint without dialing. Start calls it when
// it was not called before; calling it first lets a caller learn the
// endpoints of all nodes before any of them dials.
func (t *Transport) Listen() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ln != nil {
		return nil
	}
	ln, err := net.Listen("tcp", t.cfg.Listen)
	if err != nil {
		return err
	}
	t.ln = ln
	return nil
}

// SetPeers replaces the peer list; it must be called before Start.
func (t *Transport) SetPeers(peers []Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.Peers = append([]Peer(nil), peers...)
}

// Start listens and starts dialing the peers.
func (t *Transport) Start() error {
	if err := t.Listen(); err != nil {
		return err
	}
	t.mu.Lock()
	ln, peers := t.ln, t.cfg.Peers
	t.mu.Unlock()
	t.wg.Add(1)
	go t.acceptLoop(ln)
	for _, p := range peers {
		if t.cfg.Self.Cmp(p.Addr) < 0 {
			t.wg.Add(1)
			go t.dialLoop(p)
		}
	}
	return nil
}

// Endpoint returns the listening endpoint, or "" before Start.
func (t *Transport) Endpoint() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ln == nil {
		return ""
	}
	return t.ln.Addr().String()
}

// Close closes the listener and every connection.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	close(t.done)
	var err error
	if t.ln != nil {
		err = t.ln.Close()
	}
	conns := make([]*conn, 0, len(t.peers))
	for _, c := range t.peers { //wbft:unordered every connection is closed
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		t.drop(c, transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseShutdown, Reason: "closed"})
	}
	t.wg.Wait()
	return err
}

// SetReceiver implements transport.Transport.
func (t *Transport) SetReceiver(r transport.Receiver) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recv = r
}

// SetFrameObserver implements transport.Observed.
func (t *Transport) SetFrameObserver(o transport.FrameObserver) {
	t.mu.Lock()
	t.obs = o
	t.mu.Unlock()
}

// observer returns the frame observer, or nil.
func (t *Transport) observer() transport.FrameObserver {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.obs
}

// SetAppHandler installs the receiver of the application channel.
func (t *Transport) SetAppHandler(h AppHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.app = h
}

// PeerEvents implements transport.Transport.
func (t *Transport) PeerEvents() <-chan transport.PeerEvent { return t.events }

// Peers implements transport.Transport.
func (t *Transport) Peers() []transport.PeerInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]transport.PeerInfo, 0, len(t.peers))
	for _, c := range t.peers { //wbft:unordered sorted below
		out = append(out, transport.PeerInfo{Addr: c.peer, Caps: []string{helloMagic}, Static: true, ConnectedSince: c.since})
	}
	slices.SortFunc(out, func(a, b transport.PeerInfo) int { return a.Addr.Cmp(b.Addr) })
	return out
}

// Send implements transport.Transport.
func (t *Transport) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	return t.send(peers, frame{ch: chanConsensus, code: code, payload: payload})
}

// SendApp queues a message of the application channel for each peer.
func (t *Transport) SendApp(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	return t.send(peers, frame{ch: chanApp, code: code, payload: payload})
}

func (t *Transport) send(peers []types.Address, f frame) []transport.SendResult {
	res := make([]transport.SendResult, len(peers))
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, p := range peers {
		c := t.peers[p]
		if c == nil {
			res[i] = transport.NotAttached
			continue
		}
		select {
		case c.out <- f:
			res[i] = transport.Queued
		default:
			res[i] = transport.QueueFull
		}
	}
	return res
}

// Disconnect implements transport.Transport. A dialed peer is dialed again.
func (t *Transport) Disconnect(peer types.Address, reason string) {
	t.mu.Lock()
	c := t.peers[peer]
	t.mu.Unlock()
	if c != nil {
		t.drop(c, transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseCause(reason), Reason: reason})
	}
}

func (t *Transport) acceptLoop(ln net.Listener) {
	defer t.wg.Done()
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			peer, err := t.handshake(nc)
			if err != nil {
				t.log.Debug("refused connection", "remote", nc.RemoteAddr(), "err", err)
				_ = nc.Close()
				return
			}
			t.run(peer, nc)
		}()
	}
}

func (t *Transport) dialLoop(p Peer) {
	defer t.wg.Done()
	for {
		select {
		case <-t.done:
			return
		default:
		}
		nc, err := net.DialTimeout("tcp", p.Endpoint, 2*time.Second)
		if err == nil {
			var peer types.Address
			if peer, err = t.handshake(nc); err == nil && peer != p.Addr {
				err = fmt.Errorf("devnet: %s claims %x, want %x", p.Endpoint, peer, p.Addr)
			}
			if err != nil {
				_ = nc.Close()
			} else {
				t.run(peer, nc) // returns when the connection ends
			}
		}
		select {
		case <-t.done:
			return
		case <-time.After(t.cfg.RedialInterval):
		}
	}
}

// handshake exchanges hello messages: magic, network name and address.
func (t *Transport) handshake(nc net.Conn) (types.Address, error) {
	var peer types.Address
	_ = nc.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = nc.SetDeadline(time.Time{}) }()
	hello := append([]byte(helloMagic), byte(len(t.cfg.Network)))
	hello = append(hello, t.cfg.Network...)
	hello = append(hello, t.cfg.Self[:]...)
	if _, err := nc.Write(hello); err != nil {
		return peer, err
	}
	magic := make([]byte, len(helloMagic)+1)
	if _, err := io.ReadFull(nc, magic); err != nil {
		return peer, err
	}
	if string(magic[:len(helloMagic)]) != helloMagic {
		return peer, errors.New("devnet: not a devnet peer")
	}
	name := make([]byte, int(magic[len(helloMagic)]))
	if _, err := io.ReadFull(nc, name); err != nil {
		return peer, err
	}
	if string(name) != t.cfg.Network {
		return peer, fmt.Errorf("devnet: peer is on network %q", name)
	}
	if _, err := io.ReadFull(nc, peer[:]); err != nil {
		return peer, err
	}
	if peer == t.cfg.Self {
		return peer, errors.New("devnet: connection to self")
	}
	if !t.known(peer) {
		return peer, fmt.Errorf("devnet: unknown peer %x", peer)
	}
	return peer, nil
}

func (t *Transport) known(a types.Address) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.cfg.Peers {
		if p.Addr == a {
			return true
		}
	}
	return false
}

// run serves a connection until it ends.
func (t *Transport) run(peer types.Address, nc net.Conn) {
	c := &conn{peer: peer, c: nc, out: make(chan frame, t.cfg.QueueSize), since: time.Now(), gone: make(chan struct{})}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = nc.Close()
		return
	}
	old := t.peers[peer]
	t.peers[peer] = c
	t.mu.Unlock()
	if old != nil {
		t.drop(old, transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseReplaced, Reason: "replaced"})
	}
	if o := t.observer(); o != nil {
		o.Attached(peer, nc.RemoteAddr().String())
	}
	t.event(transport.PeerEvent{Addr: peer, Attached: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.writeLoop(c)
	}()
	t.drop(c, t.readLoop(c))
	<-done
}

func (t *Transport) event(e transport.PeerEvent) {
	select {
	case t.events <- e:
	default:
		t.log.Warn("peer event dropped", "peer", e.Addr, "attached", e.Attached)
	}
}

// drop closes a connection once and removes it from the table.
func (t *Transport) drop(c *conn, how transport.Close) {
	c.once.Do(func() {
		close(c.gone)
		_ = c.c.Close()
		t.mu.Lock()
		removed := t.peers[c.peer] == c
		if removed {
			delete(t.peers, c.peer)
		}
		t.mu.Unlock()
		if removed {
			if o := t.observer(); o != nil {
				transport.ReportClosed(o, c.peer, how)
			}
			t.log.Debug("peer disconnected", "peer", c.peer, "by", how.By, "cause", how.Cause, "reason", how.Reason)
			t.event(transport.PeerEvent{Addr: c.peer, Attached: false})
		}
	})
}

func (t *Transport) writeLoop(c *conn) {
	w := bufio.NewWriter(c.c)
	var hdr [1 + 2*binary.MaxVarintLen64]byte
	for {
		select {
		case <-c.gone:
			return
		case f := <-c.out:
			hdr[0] = f.ch
			n := 1 + binary.PutUvarint(hdr[1:], f.code)
			n += binary.PutUvarint(hdr[n:], uint64(len(f.payload)))
			_, err := w.Write(hdr[:n])
			if err == nil {
				_, err = w.Write(f.payload)
			}
			if o := t.observer(); o != nil && f.ch == chanConsensus {
				res := transport.WriteOK
				if err != nil {
					res = transport.WriteError
				}
				o.Wrote(c.peer, f.code, f.payload, res)
			}
			if err != nil {
				t.drop(c, writeClose)
				return
			}
			if len(c.out) == 0 {
				if err := w.Flush(); err != nil {
					t.drop(c, writeClose)
					return
				}
			}
		}
	}
}

var writeClose = transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseWriteError, Reason: "write"}

// readLoop reads frames until the connection ends and returns how it ended:
// the peer closed it (end of stream), the read failed (unknown: a close of
// the node's own may have caused it), or a frame made the node close it.
func (t *Transport) readLoop(c *conn) transport.Close {
	r := bufio.NewReader(c.c)
	ended := func(err error) transport.Close {
		if errors.Is(err, io.EOF) {
			return transport.Close{By: transport.ClosedByPeer, Reason: "read: " + err.Error()}
		}
		return transport.Close{By: transport.ClosedByUnknown, Reason: "read: " + err.Error()}
	}
	frame := func(reason string) transport.Close {
		return transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseFrame, Reason: reason}
	}
	for {
		ch, err := r.ReadByte()
		if err != nil {
			return ended(err)
		}
		code, err := binary.ReadUvarint(r)
		if err != nil {
			return ended(err)
		}
		size, err := binary.ReadUvarint(r)
		if err != nil {
			return ended(err)
		}
		if size > maxFrame {
			return frame("frame over the transport limit")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return ended(err)
		}
		switch ch {
		case chanConsensus:
			if !t.deliver(c.peer, code, payload) {
				return frame("frame stage")
			}
		case chanApp:
			t.mu.Lock()
			h := t.app
			t.mu.Unlock()
			if h != nil {
				h(c.peer, code, payload)
			}
		default:
			return transport.Close{By: transport.ClosedBySelf, Cause: transport.CloseOther, Reason: "unknown channel"}
		}
	}
}

// deliver passes a consensus frame through the frame stage to the receiver;
// it reports false when the connection must be closed.
func (t *Transport) deliver(peer types.Address, code uint64, payload []byte) bool {
	t.mu.Lock()
	r, o := t.recv, t.obs
	t.mu.Unlock()
	data, dc, act, reason := transport.DecodeFrame(code, payload)
	switch act {
	case transport.FrameDisconnect:
		t.log.Debug("frame closes the connection", "peer", peer, "reason", reason)
		if o != nil {
			o.Received(peer, code, len(payload), payload, transport.OfferFrameDisconnect)
		}
		return false
	case transport.FrameDrop:
		if o != nil {
			o.Received(peer, code, len(payload), payload, transport.OfferFrameIgnore)
		}
		return true
	}
	offer := transport.OfferQueued
	if r != nil && !r.Offer(transport.Inbound{Peer: peer, Code: dc, Payload: data, RecvMono: time.Since(t.start)}) {
		offer = transport.OfferQueueFull
	}
	if o != nil {
		o.Received(peer, code, len(payload), payload, offer)
	}
	return true
}
