package kvstore

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"

	"github.com/0xmhha/wbft/node"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/types"
)

// NodeConfig configures a kvstore node.
type NodeConfig struct {
	// Home holds the node's data: consensus/ (write-ahead log and sign
	// state) and app/ (blocks).
	Home string
	// Genesis is the chain's genesis.
	Genesis *Genesis
	// KeyFile is the node key (64 hex characters); empty runs a node that
	// does not sign.
	KeyFile string
	// Self is the address of the node key; it identifies the node on the
	// development transport.
	Self types.Address
	// Listen is the transport endpoint; empty runs without a network.
	Listen string
	// Network names the development network.
	Network string
	// Peers are the other nodes.
	Peers []devnet.Peer
	// TakeoverGuard sets the sign floor for a key without its sign state.
	TakeoverGuard bool
	Logger        *slog.Logger
}

// Node is a kvstore application with its consensus node.
type Node struct {
	App  *App
	Node *node.Node
	tr   *devnet.Transport
	net  *network
}

// NewNode opens the application and assembles the consensus node; Start
// starts both.
func NewNode(cfg NodeConfig) (*Node, error) {
	if cfg.Genesis == nil {
		return nil, errors.New("kvstore: genesis is required")
	}
	a, err := Open(filepath.Join(cfg.Home, "app"), cfg.Genesis, cfg.Logger)
	if err != nil {
		return nil, err
	}
	kn := &Node{App: a}
	deps := node.Deps{App: a, Authority: a, Admission: a.Admission(), Logger: cfg.Logger}
	if cfg.Listen != "" {
		tr, err := devnet.New(devnet.Config{Self: cfg.Self, Listen: cfg.Listen, Network: cfg.Network, Peers: cfg.Peers, Logger: cfg.Logger})
		if err != nil {
			return nil, err
		}
		kn.tr = tr
		kn.net = newNetwork(tr, a)
		deps.Transport, deps.TxTransport = tr, kn.net
	}
	n, err := node.New(node.Config{DataDir: filepath.Join(cfg.Home, "consensus"), KeyFile: cfg.KeyFile,
		TakeoverGuard: cfg.TakeoverGuard}, deps)
	if err != nil {
		return nil, err
	}
	kn.Node = n
	var peers Peers
	if kn.net != nil {
		peers = kn.net
	}
	a.Attach(n.Consensus(), peers)
	return kn, nil
}

// Start starts the consensus node and the transport.
func (kn *Node) Start(ctx context.Context) error {
	if kn.tr != nil {
		if err := kn.tr.Listen(); err != nil {
			return err
		}
	}
	if err := kn.Node.Start(ctx); err != nil {
		return err
	}
	kn.App.SetPool(kn.Node.Mempool())
	if kn.tr != nil {
		return kn.tr.Start()
	}
	return nil
}

// Endpoint returns the transport endpoint, or "" without a network.
func (kn *Node) Endpoint() string {
	if kn.tr == nil {
		return ""
	}
	return kn.tr.Endpoint()
}

// Stop stops the node and the transport.
func (kn *Node) Stop() error {
	err := kn.Node.Stop()
	if kn.tr != nil {
		err = errors.Join(err, kn.tr.Close())
		kn.net.close()
	}
	return err
}
