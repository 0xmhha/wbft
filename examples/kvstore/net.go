package kvstore

import (
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/types"
)

// Codes of the application channel of the development transport.
const (
	codeBlock     uint64 = 1 // one encoded block
	codeGetBlocks uint64 = 2 // RLP uint64: the first block number wanted
	codeTxs       uint64 = 3 // RLP list of encoded transactions
)

// syncBatch is the number of blocks sent for one request.
const syncBatch = 64

// network carries blocks and transactions over the application channel of
// a devnet transport. It implements Peers and mempool.TxTransport.
type network struct {
	t   *devnet.Transport
	app *App

	mu   sync.Mutex
	recv mempool.TxReceiver

	in   chan inbound
	done chan struct{}
	wg   sync.WaitGroup
}

type inbound struct {
	peer    types.Address
	code    uint64
	payload []byte
}

var (
	_ Peers               = (*network)(nil)
	_ mempool.TxTransport = (*network)(nil)
)

func newNetwork(t *devnet.Transport, a *App) *network {
	n := &network{t: t, app: a, in: make(chan inbound, 1024), done: make(chan struct{})}
	t.SetAppHandler(n.handle)
	n.wg.Add(1)
	go n.loop()
	return n
}

func (n *network) close() {
	close(n.done)
	n.wg.Wait()
}

// handle is called from the transport's read loop; it never blocks.
func (n *network) handle(peer types.Address, code uint64, payload []byte) {
	if code == codeTxs {
		n.mu.Lock()
		r := n.recv
		n.mu.Unlock()
		var txs [][]byte
		if r != nil && rlp.DecodeStrict(payload, &txs) == nil {
			r.OfferTxs(peer, txs)
		}
		return
	}
	select {
	case n.in <- inbound{peer, code, payload}:
	default:
	}
}

func (n *network) loop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case m := <-n.in:
			switch m.code {
			case codeBlock:
				if b, err := codec.DecodeBlock(m.payload); err == nil {
					if err := n.app.ImportBlock(m.peer, b); err != nil {
						n.app.log.Debug("block import failed", "peer", m.peer, "number", b.Header.Number, "err", err)
					}
				}
			case codeGetBlocks:
				var from uint64
				if rlp.DecodeStrict(m.payload, &from) == nil {
					n.serve(m.peer, from)
				}
			}
		}
	}
}

// serve sends up to syncBatch blocks from number from to peer.
func (n *network) serve(peer types.Address, from uint64) {
	for i := from; i < from+syncBatch; i++ {
		b := n.app.BlockByNumber(i)
		if b == nil {
			return
		}
		if raw, err := codec.EncodeBlock(b); err == nil {
			n.t.SendApp([]types.Address{peer}, codeBlock, raw)
		}
	}
}

func (n *network) all() []types.Address {
	ps := n.t.Peers()
	out := make([]types.Address, len(ps))
	for i, p := range ps {
		out[i] = p.Addr
	}
	return out
}

// AnnounceBlock implements Peers.
func (n *network) AnnounceBlock(b *types.Block) {
	if raw, err := codec.EncodeBlock(b); err == nil {
		n.t.SendApp(n.all(), codeBlock, raw)
	}
}

// RequestBlocks implements Peers.
func (n *network) RequestBlocks(peer types.Address, from uint64) {
	if raw, err := rlp.Encode(from); err == nil {
		n.t.SendApp([]types.Address{peer}, codeGetBlocks, raw)
	}
}

// SetTxReceiver implements mempool.TxTransport.
func (n *network) SetTxReceiver(r mempool.TxReceiver) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.recv = r
}

// Propagate implements mempool.TxTransport: every peer gets every new
// transaction.
func (n *network) Propagate(txs []mempool.OutTx) {
	raw := make([][]byte, len(txs))
	for i, t := range txs {
		raw[i] = t.Tx
	}
	if b, err := rlp.Encode(raw); err == nil {
		n.t.SendApp(n.all(), codeTxs, b)
	}
}
