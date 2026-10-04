package node

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"runtime/debug"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/evidence"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// backend implements rpc.Backend for a node.
type backend struct{ n *Node }

var _ rpc.Backend = backend{}

// APIs returns the RPC services of the node for the application's RPC
// server.
func (n *Node) APIs() []rpc.API { return rpc.APIs(backend{n}) }

func (b backend) NodeInfo() rpc.NodeInfo {
	n := b.n
	info := rpc.NodeInfo{Impl: "wbft", Address: n.Address(), Mode: n.mode(), Version: moduleVersion(), Build: "cgo",
		Improvements: n.improvements()}
	n.mu.Lock()
	info.Validator = n.signer != nil
	if n.signer != nil {
		info.BLSPublicKey = "0x" + hex.EncodeToString(n.signer.BLSPublicKey())
	}
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

func (b backend) Evidence(from, to *big.Int) ([]evidence.Record, error) {
	b.n.mu.Lock()
	s := b.n.evid
	b.n.mu.Unlock()
	if s == nil {
		return []evidence.Record{}, nil
	}
	return s.Range(from, to)
}

func (b backend) Rejections(from, to *big.Int) ([]rejection.Record, error) {
	b.n.mu.Lock()
	s := b.n.rej
	b.n.mu.Unlock()
	if s == nil {
		return []rejection.Record{}, nil
	}
	return s.Range(from, to)
}

func (b backend) HeaderCopy(hash types.Hash) (*rpc.HeaderCopyResult, error) {
	h := b.n.d.App.HeaderByHash(hash)
	if h == nil {
		return nil, nil
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	seal := func(s *types.AggregatedSeal) *rpc.SealCopy {
		if s == nil {
			return nil
		}
		return &rpc.SealCopy{Sealers: s.Sealers.Sealers(), Signature: "0x" + hex.EncodeToString(s.Signature)}
	}
	path := "unknown"
	if p, ok := b.n.paths.get(hash); ok {
		path = p.String()
	}
	return &rpc.HeaderCopyResult{Number: h.Number.String(), Hash: "0x" + hex.EncodeToString(hash.Bytes()), Round: x.Round,
		PreparedSeal: seal(x.PreparedSeal), CommittedSeal: seal(x.CommittedSeal), Path: path}, nil
}

func (b backend) Events(from uint64, limit int) []json.RawMessage { return b.n.ring.since(from, limit) }

func (b backend) Chain() types.ChainReader { return b.n.d.App }

func (b backend) ChainConfig() *types.Config {
	b.n.mu.Lock()
	defer b.n.mu.Unlock()
	return b.n.chainCfg
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

// moduleVersion is the version of the wbft module in the running binary:
// its module version as a dependency, or the VCS revision when wbft is the
// main module ("unknown" without build information).
func moduleVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	const path = "github.com/0xmhha/wbft"
	for _, d := range bi.Deps {
		if d.Path == path {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	if bi.Main.Path == path {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
		return bi.Main.Version
	}
	return "unknown"
}
