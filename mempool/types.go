package mempool

import (
	"context"

	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// AdmissionHook is implemented by the application. It decides whether a
// transaction is valid; the pool never interprets transaction bytes.
type AdmissionHook interface {
	// TxKey returns the identity of a transaction (for Ethereum: the
	// transaction hash). It is pure and cheap.
	TxKey(tx []byte) (types.Hash, error)
	// CheckTx validates tx against the application's head state.
	CheckTx(ctx context.Context, req CheckRequest) CheckResponse
}

// RecheckScoper is an optional AdmissionHook extension that limits the
// recheck after a new head to some senders.
type RecheckScoper interface {
	Scope(u BlockUpdate) []types.Address
}

// CheckKind tells a first check from a recheck after a new head.
type CheckKind uint8

// Check kinds.
const (
	CheckNew CheckKind = iota
	CheckRecheck
)

// Origin tells where a transaction came from.
type Origin uint8

// Origins.
const (
	OriginRemote Origin = iota // received from a peer
	OriginLocal                // submitted through the node's RPC
)

// CheckRequest is the input of CheckTx.
type CheckRequest struct {
	Tx     []byte
	Key    types.Hash
	Kind   CheckKind
	Origin Origin
}

// CheckCode is the verdict of CheckTx.
type CheckCode uint8

// Check codes.
const (
	CodeOK        CheckCode = iota // keep; eligible for gossip
	CodeReject                     // drop; do not gossip
	CodeTemporary                  // cannot decide now; drop without penalty
)

// CheckResponse is the result of CheckTx.
type CheckResponse struct {
	Code   CheckCode
	Reason string // for logs and RPC
	Meta   TxMeta // meaningful when Code is CodeOK
}

// TxMeta is what the pool and the ordering policy know about a transaction.
type TxMeta struct {
	Sender     types.Address
	Nonce      uint64
	StateNonce uint64 // sender nonce in the head state of this check
	GasLimit   uint64
	Size       int
	Hints      OrderHints
}

// OrderHints are price fields for ordering policies; the pool does not read
// them.
type OrderHints struct {
	TipCap, FeeCap *uint256.Int
	CachedTip      *uint256.Int
	Type           uint8
}

// PooledTx is a transaction in the pool.
type PooledTx struct {
	Key     types.Hash
	Tx      []byte
	Meta    TxMeta
	Arrival uint64 // admission order within the pool
	Local   bool
}

// Pool is the transaction pool the application calls. All methods are safe
// for concurrent use.
type Pool interface {
	// Add admits a locally submitted transaction and returns the response
	// of its check.
	Add(ctx context.Context, tx []byte) (CheckResponse, error)
	// Proposal returns an iterator over transactions for a block being
	// built, over a copy of the executable transactions.
	Proposal(ctx context.Context, req ProposalRequest) (ProposalIter, error)
	// Update removes the transactions of a new canonical block and starts
	// a recheck of the rest.
	Update(ctx context.Context, u BlockUpdate) error
	// Get returns the transactions with those keys (nil for unknown ones).
	Get(keys []types.Hash) [][]byte
	// Has reports whether the pool holds the transaction.
	Has(key types.Hash) bool
	// PendingNonce returns the next nonce of the sender after its
	// executable transactions.
	PendingNonce(sender types.Address) (uint64, bool)
	// Content returns the pooled transactions of one sender, or of all when
	// sender is nil.
	Content(sender *types.Address) PoolContent
	// SubscribeNew delivers the keys of newly admitted transactions.
	SubscribeNew(ch chan<- []types.Hash) (unsubscribe func())
}

// PoolContent lists pooled transactions by sender.
type PoolContent struct {
	Pending map[types.Address][]PooledTx // executable, in nonce order
	Queued  map[types.Address][]PooledTx // waiting for a missing nonce
}

// ProposalRequest bounds a proposal.
type ProposalRequest struct {
	// MaxGas bounds the sum of the declared gas limits; 0 is no bound.
	MaxGas uint64
	// MaxBytes bounds the sum of the sizes; 0 uses DefaultProposalBytes.
	MaxBytes int
	// Env gives the ordering policy the facts of the build state; nil
	// includes every transaction.
	Env ProposalEnv
}

// DefaultProposalBytes is the default byte bound of a proposal, below the
// largest consensus message.
const DefaultProposalBytes = 8 << 20

// ProposalEnv gives the ordering policy the facts that come from the state
// a block is built on.
type ProposalEnv interface {
	Class(sender types.Address) uint8
	Include(meta TxMeta) bool
	Local(sender types.Address) bool
}

// ExecOutcome is the builder's report on one transaction.
type ExecOutcome uint8

// Execution outcomes.
const (
	Included   ExecOutcome = iota // executed and included
	SkipTx                        // skip this transaction, continue with the sender
	DropSender                    // skip the rest of this sender for this block
)

// ProposalIter is used by one builder goroutine. A transaction that is not
// reported before the next call of Next counts as Included.
type ProposalIter interface {
	Next() (key types.Hash, tx []byte, meta TxMeta, ok bool)
	Report(key types.Hash, out ExecOutcome)
}

// BlockUpdate describes a new canonical block.
type BlockUpdate struct {
	Number   types.Height
	Hash     types.Hash
	Included []types.Hash // keys of the transactions of the block, in order
}

// OrderingPolicy orders the transactions of a proposal. Ordering is not a
// validity rule; nodes may use different policies.
type OrderingPolicy interface {
	Name() string
	// NewIterator orders the executable lists (per sender, nonce order).
	NewIterator(heads []SenderHead, env ProposalEnv) Iterator
	// Replace decides whether a new transaction replaces a pooled one with
	// the same sender and nonce.
	Replace(old, new TxMeta) bool
	// Evict chooses n transactions to drop when the pool is full.
	Evict(stats PoolStats, n int) []types.Hash
}

// SenderHead is the executable list of one sender, in nonce order.
type SenderHead struct {
	Sender types.Address
	Txs    []PooledTx
}

// Iterator is the ordering of one proposal. Report tells the policy what
// the builder did with the last transaction.
type Iterator interface {
	Next() (PooledTx, bool)
	Report(key types.Hash, out ExecOutcome)
}

// PoolStats describes the pool for eviction.
type PoolStats struct {
	Txs   []PooledTx // every pooled transaction, in arrival order
	Bytes int
}

// TxTransport is implemented by the application's transaction gossip
// adapter.
type TxTransport interface {
	// SetTxReceiver installs the sink of transactions from peers.
	SetTxReceiver(r TxReceiver)
	// Propagate hands newly admitted transactions to the adapter. It never
	// blocks.
	Propagate(txs []OutTx)
}

// TxReceiver takes transactions from peers.
type TxReceiver interface {
	// OfferTxs never blocks. It returns how many transactions were queued
	// for admission.
	OfferTxs(peer types.Address, txs [][]byte) int
}

// OutTx is a newly admitted transaction to propagate.
type OutTx struct {
	Key  types.Hash
	Tx   []byte
	Meta TxMeta
}
