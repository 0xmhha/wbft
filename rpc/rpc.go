package rpc

import (
	"math/big"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Backend is what the RPC services read. Package node implements it. No
// method waits for the consensus goroutine.
type Backend interface {
	NodeInfo() NodeInfo
	// ConsensusState returns the latest summary of the core, or nil when
	// the node runs no core.
	ConsensusState() *consensus.Snapshot
	// Peers returns the attached peers, or nil without a transport.
	Peers() []transport.PeerInfo
}

// NodeInfo describes the node.
type NodeInfo struct {
	Impl        string        `json:"impl"`
	Address     types.Address `json:"address"`
	Validator   bool          `json:"validator"`
	ChainID     *big.Int      `json:"chainId"`
	GenesisHash types.Hash    `json:"genesisHash"`
	Head        HeadInfo      `json:"head"`
	SignFloor   string        `json:"signFloor,omitempty"`
}

// HeadInfo is the application head.
type HeadInfo struct {
	Number string     `json:"number"`
	Hash   types.Hash `json:"hash"`
}

// ConsensusState is the JSON form of the core's summary.
type ConsensusState struct {
	Running    bool            `json:"running"`
	Sequence   string          `json:"sequence,omitempty"`
	Round      string          `json:"round,omitempty"`
	State      string          `json:"state,omitempty"`
	Proposer   *types.Address  `json:"proposer,omitempty"`
	IsProposer bool            `json:"isProposer"`
	Validators []types.Address `json:"validators,omitempty"`
}

// PeerInfo is the JSON form of an attached peer.
type PeerInfo struct {
	Address        types.Address `json:"address"`
	Caps           []string      `json:"caps"`
	ConnectedSince string        `json:"connectedSince"`
}

// API is one namespace of services.
type API struct {
	Namespace string
	Service   any
}

// APIs returns the wbft namespace for the backend.
func APIs(b Backend) []API {
	return []API{{Namespace: "wbft", Service: &Service{b: b}}}
}

// Service is the wbft namespace: wbft_nodeInfo, wbft_consensusState and
// wbft_peers. It is read-only.
type Service struct{ b Backend }

// NodeInfo is wbft_nodeInfo.
func (s *Service) NodeInfo() NodeInfo { return s.b.NodeInfo() }

// ConsensusState is wbft_consensusState.
func (s *Service) ConsensusState() ConsensusState {
	snap := s.b.ConsensusState()
	if snap == nil || !snap.Running {
		return ConsensusState{}
	}
	out := ConsensusState{Running: true, Sequence: snap.View.Sequence.String(), Round: snap.View.Round.String(),
		State: snap.State.String(), IsProposer: snap.IsProposer}
	p := snap.Proposer
	out.Proposer = &p
	if snap.Validators != nil {
		out.Validators = snap.Validators.Addresses()
	}
	return out
}

// Peers is wbft_peers.
func (s *Service) Peers() []PeerInfo {
	out := []PeerInfo{}
	for _, p := range s.b.Peers() {
		out = append(out, PeerInfo{Address: p.Addr, Caps: p.Caps, ConnectedSince: p.ConnectedSince.UTC().Format("2006-01-02T15:04:05Z")})
	}
	return out
}
