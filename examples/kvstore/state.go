package kvstore

import (
	"maps"
	"slices"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// State is the key-value state after a block. It is immutable; Apply
// returns a new state.
type State struct {
	kv     map[string]string
	nonces map[types.Address]uint64
}

// emptyState is the state of the genesis block.
func emptyState() *State { return &State{kv: map[string]string{}, nonces: map[types.Address]uint64{}} }

// Get returns the value of a key.
func (s *State) Get(key string) (string, bool) {
	v, ok := s.kv[key]
	return v, ok
}

// Nonce returns the next nonce of a sender.
func (s *State) Nonce(a types.Address) uint64 { return s.nonces[a] }

// Apply executes transactions in order. A transaction whose nonce is not
// the sender's next nonce fails the whole list.
func (s *State) Apply(txs []Tx) (*State, error) {
	next := &State{kv: maps.Clone(s.kv), nonces: maps.Clone(s.nonces)}
	for _, t := range txs {
		if t.Nonce != next.nonces[t.From] {
			return nil, ErrTx
		}
		next.nonces[t.From]++
		next.kv[t.Key] = t.Value
	}
	return next, nil
}

// Root is the commitment to the state written into the header: keccak256
// of the RLP list of the sorted key-value pairs and the sorted nonces.
func (s *State) Root() types.Hash {
	type kvItem struct{ K, V string }
	type nonceItem struct {
		A types.Address
		N uint64
	}
	var kvs []kvItem
	for _, k := range slices.Sorted(maps.Keys(s.kv)) {
		kvs = append(kvs, kvItem{k, s.kv[k]})
	}
	var ns []nonceItem
	for _, a := range slices.SortedFunc(maps.Keys(s.nonces), types.Address.Cmp) {
		ns = append(ns, nonceItem{a, s.nonces[a]})
	}
	b, err := rlp.Encode([]any{kvs, ns})
	if err != nil {
		panic(err) // plain strings and integers always encode
	}
	return keccak.Sum256(b)
}
