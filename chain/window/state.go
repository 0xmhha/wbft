package window

import (
	"bytes"
	"math/big"
	"sort"

	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

type memberRLP struct {
	Index   uint64
	Address types.Address
	Key     []byte
}
type targetRLP struct {
	Height  *big.Int
	Hash    types.Hash
	Round   uint32
	Members []memberRLP
	Prepare []byte
	Commit  []byte
}
type stateRLP struct {
	Version uint64
	Policy  types.Hash
	Height  *big.Int
	Parent  types.Hash
	Settled *big.Int
	Matured *big.Int
	Counts  []wire.Counts
	Pending []wire.Counts
	Open    []targetRLP
}

// State is an immutable verified observation state. Its carrier hash is kept
// separately from the state root, avoiding a self-referential header hash.
type State struct {
	data   stateRLP
	anchor types.Hash
}

func (s *State) Height() types.Height         { return types.MustHeightFromBig(s.data.Height) }
func (s *State) SettledThrough() types.Height { return types.MustHeightFromBig(s.data.Settled) }
func (s *State) MaturedThrough() types.Height { return types.MustHeightFromBig(s.data.Matured) }

// Counts returns a copy of the settled cumulative observation counts. False
// means NO_HISTORY, not nonparticipation. Pending counts are not settled yet.
func (s *State) Counts(address types.Address) (wire.Counts, bool) {
	for _, r := range s.data.Counts {
		if r.Address == address {
			return copyCount(r), true
		}
	}
	return zeroCount(address), false
}
func copyCount(r wire.Counts) wire.Counts {
	return wire.Counts{Address: r.Address, EligiblePrepare: new(big.Int).Set(r.EligiblePrepare), EligibleCommit: new(big.Int).Set(r.EligibleCommit), ObservedPrepare: new(big.Int).Set(r.ObservedPrepare), ObservedCommit: new(big.Int).Set(r.ObservedCommit)}
}
func zeroCount(a types.Address) wire.Counts {
	return wire.Counts{Address: a, EligiblePrepare: new(big.Int), EligibleCommit: new(big.Int), ObservedPrepare: new(big.Int), ObservedCommit: new(big.Int)}
}
func validRows(rows []wire.Counts, limit uint32) bool {
	if uint64(len(rows)) > uint64(limit) {
		return false
	}
	for i, r := range rows {
		for _, n := range []*big.Int{r.EligiblePrepare, r.EligibleCommit, r.ObservedPrepare, r.ObservedCommit} {
			if n == nil || n.Sign() < 0 {
				return false
			}
		}
		if r.ObservedPrepare.Cmp(r.EligiblePrepare) > 0 || r.ObservedCommit.Cmp(r.EligibleCommit) > 0 || (r.EligiblePrepare.Sign() == 0 && r.EligibleCommit.Sign() == 0) || (i > 0 && bytes.Compare(rows[i-1].Address[:], r.Address[:]) >= 0) {
			return false
		}
	}
	return true
}
func addRows(left, right []wire.Counts) []wire.Counts {
	rows := make([]wire.Counts, 0, len(left)+len(right))
	for _, r := range left {
		rows = append(rows, copyCount(r))
	}
	for _, r := range right {
		rows = append(rows, copyCount(r))
	}
	sort.SliceStable(rows, func(i, j int) bool { return bytes.Compare(rows[i].Address[:], rows[j].Address[:]) < 0 })
	out := make([]wire.Counts, 0, len(rows))
	for _, r := range rows {
		if len(out) > 0 && out[len(out)-1].Address == r.Address {
			p := &out[len(out)-1]
			p.EligiblePrepare.Add(p.EligiblePrepare, r.EligiblePrepare)
			p.EligibleCommit.Add(p.EligibleCommit, r.EligibleCommit)
			p.ObservedPrepare.Add(p.ObservedPrepare, r.ObservedPrepare)
			p.ObservedCommit.Add(p.ObservedCommit, r.ObservedCommit)
		} else {
			out = append(out, r)
		}
	}
	return out
}
func union(a, b []byte) []byte {
	if len(a) < len(b) {
		a = append(a, make([]byte, len(b)-len(a))...)
	}
	for i, v := range b {
		a[i] |= v
	}
	return a
}
func targetCounts(t targetRLP) []wire.Counts {
	var rows []wire.Counts
	for i, m := range t.Members {
		r := zeroCount(m.Address)
		r.EligiblePrepare.SetUint64(1)
		r.EligibleCommit.SetUint64(1)
		if types.SealerSet(t.Prepare).IsSealer(uint32(i)) {
			r.ObservedPrepare.SetUint64(1)
		}
		if types.SealerSet(t.Commit).IsSealer(uint32(i)) {
			r.ObservedCommit.SetUint64(1)
		}
		rows = append(rows, r)
	}
	return addRows(nil, rows)
}
func (e *Engine) stateBytes(s *State) ([]byte, error) {
	if s == nil {
		return nil, ErrState
	}
	d := s.data
	if d.Version != 1 || d.Policy != e.policy || d.Height == nil || d.Settled == nil || d.Matured == nil || d.Height.Sign() < 0 || d.Settled.Sign() < 0 || d.Settled.Cmp(d.Matured) > 0 || d.Matured.Cmp(d.Height) > 0 || !validRows(d.Counts, e.cfg.AddressRows) || !validRows(d.Pending, e.cfg.AddressRows) {
		return nil, ErrState
	}
	before, _ := e.cfg.Activation.Sub(types.HeightFromUint64(1))
	if d.Settled.Cmp(before.Big()) < 0 || uint64(len(d.Open)) >= e.cfg.Window {
		return nil, ErrState
	}
	next := new(big.Int).Add(d.Matured, big.NewInt(1))
	for _, t := range d.Open {
		if t.Height == nil || t.Height.Cmp(next) != 0 || t.Height.Cmp(d.Height) >= 0 || len(t.Members) == 0 || uint64(len(t.Members)) > uint64(e.cfg.Codec.Validators) {
			return nil, ErrState
		}
		for i, m := range t.Members {
			if m.Index != uint64(i) || len(m.Key) != 48 {
				return nil, ErrState
			}
		}
		for _, bitmap := range [][]byte{t.Prepare, t.Commit} {
			if len(bitmap) > 0 && bitmap[len(bitmap)-1] == 0 {
				return nil, ErrState
			}
			if uint64(len(bitmap)) > (uint64(len(t.Members))+7)/8 {
				return nil, ErrState
			}
			for _, i := range types.SealerSet(bitmap).Sealers() {
				if uint64(i) >= uint64(len(t.Members)) {
					return nil, ErrState
				}
			}
		}
		next.Add(next, big.NewInt(1))
	}
	if d.Height.Cmp(before.Big()) > 0 && next.Cmp(d.Height) != 0 {
		return nil, ErrState
	}
	b, err := rlp.Encode(d)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > e.cfg.StateBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// Root commits canonical state including policy and parent lineage. It does
// not establish the authenticity of a header that happens to carry this root.
func (e *Engine) Root(s *State) (types.Hash, error) {
	b, err := e.stateBytes(s)
	if err != nil {
		return types.Hash{}, err
	}
	encoded, err := rlp.Encode([]any{[]byte("WBFT-PARTICIPATION-STATE/1"), rlp.RawValue(b)})
	if err != nil {
		return types.Hash{}, err
	}
	return keccak.Sum256(encoded), nil
}
func (e *Engine) clone(s *State) (*State, error) {
	b, err := e.stateBytes(s)
	if err != nil {
		return nil, err
	}
	var d stateRLP
	if err = rlp.DecodeStrict(b, &d); err != nil {
		return nil, err
	}
	return &State{d, s.anchor}, nil
}
