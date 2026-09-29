package node

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/rpc"
)

// backend implements rpc.Backend for a node.
type backend struct{ n *Node }

var _ rpc.Backend = backend{}

// APIs returns the RPC services of the node for the application's RPC
// server.
func (n *Node) APIs() []rpc.API { return rpc.APIs(backend{n}) }

func (b backend) NodeInfo() rpc.NodeInfo {
	n := b.n
	info := rpc.NodeInfo{Impl: "wbft", Address: n.Address()}
	n.mu.Lock()
	info.Validator = n.signer != nil
	info.ChainID, info.GenesisHash = n.info.ChainID, n.info.GenesisHash
	n.mu.Unlock()
	if h := n.d.App.Head(); h != nil {
		info.Head = rpc.HeadInfo{Number: h.Number.String(), Hash: codec.BlockHash(h)}
	}
	if f, ok := n.SignFloor(); ok {
		info.SignFloor = f.String()
	}
	return info
}

func (b backend) ConsensusState() *consensus.Snapshot {
	if r := b.n.Runner(); r != nil {
		return r.Snapshot()
	}
	return nil
}

func (b backend) Peers() []transport.PeerInfo {
	if b.n.d.Transport == nil {
		return nil
	}
	return b.n.d.Transport.Peers()
}
