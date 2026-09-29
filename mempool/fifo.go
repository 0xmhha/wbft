package mempool

import (
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/types"
)

// FIFO is the name of the built-in ordering policy.
const FIFO = "fifo"

// fifo orders senders by the arrival of their first executable transaction
// and each sender by nonce. It keeps the first transaction of a nonce and
// evicts the latest arrivals.
type fifo struct{}

func (fifo) Name() string { return FIFO }

func (fifo) Replace(TxMeta, TxMeta) bool { return false }

func (fifo) Evict(stats PoolStats, n int) []types.Hash {
	out := make([]types.Hash, 0, n)
	for i := len(stats.Txs) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, stats.Txs[i].Key)
	}
	return out
}

func (fifo) NewIterator(heads []SenderHead, _ ProposalEnv) Iterator {
	hs := make([]SenderHead, 0, len(heads))
	for _, h := range heads {
		if len(h.Txs) > 0 {
			hs = append(hs, h)
		}
	}
	slices.SortStableFunc(hs, func(a, b SenderHead) int {
		if a.Txs[0].Arrival != b.Txs[0].Arrival {
			if a.Txs[0].Arrival < b.Txs[0].Arrival {
				return -1
			}
			return 1
		}
		return a.Sender.Cmp(b.Sender)
	})
	return &fifoIter{heads: hs}
}

// fifoIter walks the senders in order; within a sender it follows the
// nonce order until the builder drops the sender.
type fifoIter struct {
	heads []SenderHead
	s, i  int // current sender and index of the next transaction
}

func (it *fifoIter) Next() (PooledTx, bool) {
	for it.s < len(it.heads) {
		h := it.heads[it.s]
		if it.i < len(h.Txs) {
			tx := h.Txs[it.i]
			it.i++
			return tx, true
		}
		it.s, it.i = it.s+1, 0
	}
	return PooledTx{}, false
}

func (it *fifoIter) Report(_ types.Hash, out ExecOutcome) {
	if out == DropSender && it.s < len(it.heads) {
		it.s, it.i = it.s+1, 0
	}
}

// Registry maps policy names to ordering policies.
type Registry struct{ byName map[string]OrderingPolicy }

// ErrDuplicatePolicy reports two policies with the same name.
var ErrDuplicatePolicy = errors.New("mempool: duplicate ordering policy")

// ErrUnknownPolicy reports a policy name that is not registered.
var ErrUnknownPolicy = errors.New("mempool: unknown ordering policy")

// NewRegistry returns a registry with the built-in "fifo" policy and extra.
func NewRegistry(extra ...OrderingPolicy) (*Registry, error) {
	r := &Registry{byName: map[string]OrderingPolicy{FIFO: fifo{}}}
	for _, p := range extra {
		if _, ok := r.byName[p.Name()]; ok {
			return nil, fmt.Errorf("%w: %q", ErrDuplicatePolicy, p.Name())
		}
		r.byName[p.Name()] = p
	}
	return r, nil
}

// Get returns the policy with that name.
func (r *Registry) Get(name string) (OrderingPolicy, error) {
	p, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPolicy, name)
	}
	return p, nil
}
