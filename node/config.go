package node

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Config configures a Node.
type Config struct {
	// DataDir holds the durable state of the node: the write-ahead log in
	// wal/ and the sign state in privval/state.
	DataDir string
	// KeyFile is the node key in the go-stablenet nodekey format (64 hex
	// characters). Empty runs a node that never signs: it verifies headers
	// but runs no consensus core.
	KeyFile string
	// TakeoverGuard sets the sign floor at head + 1 when the sign state is
	// empty and the head is above genesis, so that a node that takes over
	// a key without its sign record signs nothing at that height
	// (privval.takeover_guard).
	TakeoverGuard bool
	// RunID names this run in the event records; empty derives one from the
	// start time.
	RunID string
	// Mempool configures the transaction pool; used when Deps.Admission is
	// set.
	Mempool MempoolConfig
	// Standalone runs the node in standalone mode, where the authority may
	// come from a native module of the application. In the default
	// (embedded) mode the node refuses an authority source marked as native
	// (source.Native): an embedded chain takes its authority from the state
	// it shares with the reference implementation.
	Standalone bool
}

// MempoolConfig configures the transaction pool of a node.
type MempoolConfig struct {
	// Ordering names the ordering policy: "fifo" (the default) or one of
	// Deps.Orderings. An unknown name refuses the start.
	Ordering string
	// Limits bound the pool.
	Limits mempool.Config
}

// Deps are the collaborators of a Node.
type Deps struct {
	// App is the application. Required.
	App app.Application
	// Authority gives the authority snapshot of the head at start-up and
	// the epoch candidates during block execution. Required.
	Authority source.AuthoritySource
	// Transport carries consensus messages; nil runs a node without peers.
	Transport transport.Transport
	// Admission validates transactions for the pool; nil runs no pool.
	Admission mempool.AdmissionHook
	// TxTransport gossips transactions; nil keeps them local.
	TxTransport mempool.TxTransport
	// Orderings are ordering policies besides the built-in "fifo".
	Orderings []mempool.OrderingPolicy
	// Events receives the event records as JSON Lines; nil drops them.
	Events io.Writer
	// Logger logs; nil discards.
	Logger *slog.Logger

	// Test hooks: the file system, the fault handler, the clock and a key
	// given directly instead of KeyFile.
	fs     fsys.FS
	faults faultpoint.Handler
	clock  runner.Clock
	key    []byte
}

// Errors of the node.
var (
	// ErrConfig reports an unusable node configuration.
	ErrConfig = errors.New("node: invalid configuration")
	// ErrStartRefused reports a start-up check that refuses to start.
	ErrStartRefused = errors.New("node: start refused")
)

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrStartRefused, fmt.Sprintf(format, args...))
}

// checkChainConfig runs the start-up checks of the chain configuration that
// do not depend on an improvement.
func checkChainConfig(cfg *types.Config) error {
	if err := cfg.CheckProposerPolicy(); err != nil {
		return refuse("%v", err)
	}
	if err := cfg.CheckTransitions(); err != nil {
		return refuse("%v", err)
	}
	if err := cfg.Init.Check(); err != nil {
		return refuse("%v", err)
	}
	return nil
}
