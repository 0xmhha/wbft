package window

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"math/big"
	"sort"
)

type maturedRLP struct {
	Height  *big.Int
	Members []types.Address
	Prepare []byte
	Commit  []byte
}
type recentState struct {
	From    *big.Int
	Targets []maturedRLP
}
type recentStateRLP struct {
	Version uint64
	Policy  types.Hash
	Height  *big.Int
	Parent  types.Hash
	Settled *big.Int
	Matured *big.Int
	Counts  []wire.Counts
	From    *big.Int
	Recent  []maturedRLP
	Open    []targetRLP
}

// NewRecent selects a separately versioned recent-matured-target policy.
// H is explicit and positive. It changes no existing cumulative checkpoint,
// chooses no production network value, and applies no economic weighting.
func NewRecent(c Config, H types.Height) (*Engine, error) {
	if H.IsZero() {
		return nil, ErrPolicy
	}
	e, err := New(c)
	if err != nil {
		return nil, err
	}
	b, err := rlp.Encode([]any{[]byte("WBFT-PARTICIPATION-POLICY/2"), uint64(2), e.policy, H.Big()})
	if err != nil {
		return nil, err
	}
	e.policy = keccak.Sum256(b)
	e.retention = types.MustHeightFromBig(H.Big())
	return e, nil
}
func (e *Engine) version() uint64 {
	if e.retention.IsZero() {
		return 1
	}
	return 2
}
func (e *Engine) windowFrom(through types.Height) types.Height {
	from := e.cfg.Activation
	if candidate, ok := through.AddUint64(1).Sub(e.retention); ok && candidate.Cmp(from) > 0 {
		from = candidate
	}
	return from
}

// Retention returns the explicit H for recent mode; false denotes cumulative.
func (e *Engine) Retention() (types.Height, bool) { return e.retention, !e.retention.IsZero() }

// SettledWindow labels the complete replacement snapshot returned by Counts.
// A recent snapshot is at most H targets ending at SettledThrough, not at the
// carrier tip. Its from value is through+1 before the first eligible settlement.
func (s *State) SettledWindow() (from, through types.Height, recent bool) {
	if s.recent == nil {
		return types.Height{}, s.SettledThrough(), false
	}
	return types.MustHeightFromBig(s.recent.From), s.SettledThrough(), true
}

// RecentWindow labels the retained matured targets; it excludes open proofs.
func (s *State) RecentWindow() (from, through types.Height, ok bool) {
	if s.recent == nil {
		return types.Height{}, types.Height{}, false
	}
	through = s.MaturedThrough()
	from = through.AddUint64(1)
	if len(s.recent.Targets) > 0 {
		from = types.MustHeightFromBig(s.recent.Targets[0].Height)
	}
	return from, through, true
}

// RecentCounts returns current retained matured observations independently of
// the last published epoch snapshot. False is NO_HISTORY in this window.
func (s *State) RecentCounts(address types.Address) (wire.Counts, bool) {
	if s.recent == nil {
		return zeroCount(address), false
	}
	for _, r := range recentRows(s.recent.Targets) {
		if r.Address == address {
			return copyCount(r), true
		}
	}
	return zeroCount(address), false
}
func recentRows(targets []maturedRLP) []wire.Counts {
	byAddress := make(map[types.Address]wire.Counts)
	var addresses []types.Address
	for _, target := range targets {
		for i, a := range target.Members {
			r, ok := byAddress[a]
			if !ok {
				r = zeroCount(a)
				byAddress[a] = r
				addresses = append(addresses, a)
			}
			r.EligiblePrepare.Add(r.EligiblePrepare, big.NewInt(1))
			r.EligibleCommit.Add(r.EligibleCommit, big.NewInt(1))
			if types.SealerSet(target.Prepare).IsSealer(uint32(i)) {
				r.ObservedPrepare.Add(r.ObservedPrepare, big.NewInt(1))
			}
			if types.SealerSet(target.Commit).IsSealer(uint32(i)) {
				r.ObservedCommit.Add(r.ObservedCommit, big.NewInt(1))
			}
		}
	}
	sort.SliceStable(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) < 0 })
	rows := make([]wire.Counts, 0, len(addresses))
	for _, a := range addresses {
		rows = append(rows, byAddress[a])
	}

	return rows
}
func (e *Engine) retain(s *State, t targetRLP) {
	record := maturedRLP{Height: new(big.Int).Set(t.Height), Prepare: bytes.Clone(t.Prepare), Commit: bytes.Clone(t.Commit)}
	for _, m := range t.Members {
		record.Members = append(record.Members, m.Address)
	}
	s.recent.Targets = append(s.recent.Targets, record)
	from := e.windowFrom(types.MustHeightFromBig(t.Height))
	cut := 0
	for cut < len(s.recent.Targets) && s.recent.Targets[cut].Height.Cmp(from.Big()) < 0 {
		cut++
	}
	if cut > 0 {
		s.recent.Targets = append([]maturedRLP(nil), s.recent.Targets[cut:]...)
	}
}
func validMaturedBitmap(bitmap []byte, members int) bool {
	if len(bitmap) > 0 && bitmap[len(bitmap)-1] == 0 {
		return false
	}
	if uint64(len(bitmap)) > (uint64(members)+7)/8 {
		return false
	}
	for _, i := range types.SealerSet(bitmap).Sealers() {
		if uint64(i) >= uint64(members) {
			return false
		}
	}
	return true
}
func (e *Engine) validateRecentState(s *State) error {
	if s.recent == nil || len(s.data.Pending) != 0 || s.recent.From == nil || s.recent.From.Cmp(e.windowFrom(s.SettledThrough()).Big()) != 0 {
		return ErrState
	}
	width := new(big.Int).Sub(new(big.Int).Add(s.data.Settled, big.NewInt(1)), s.recent.From)
	for _, r := range s.data.Counts {
		if r.EligiblePrepare.Cmp(r.EligibleCommit) != 0 || r.EligiblePrepare.Cmp(width) > 0 {
			return ErrState
		}
	}
	from := e.windowFrom(s.MaturedThrough())
	expected := new(big.Int).Sub(new(big.Int).Add(s.data.Matured, big.NewInt(1)), from.Big())
	if expected.Cmp(new(big.Int).SetUint64(uint64(len(s.recent.Targets)))) != 0 {
		return ErrState
	}
	next := from.Big()
	for _, t := range s.recent.Targets {
		if t.Height == nil || t.Height.Cmp(next) != 0 || len(t.Members) == 0 || uint64(len(t.Members)) > uint64(e.cfg.Codec.Validators) || !validMaturedBitmap(t.Prepare, len(t.Members)) || !validMaturedBitmap(t.Commit, len(t.Members)) {
			return ErrState
		}
		seen := make(map[types.Address]struct{}, len(t.Members))
		for _, a := range t.Members {
			if _, ok := seen[a]; ok {
				return ErrState
			}
			seen[a] = struct{}{}
		}
		next.Add(next, big.NewInt(1))
	}
	if !validRows(recentRows(s.recent.Targets), e.cfg.AddressRows) {
		return ErrCapacity
	}
	return nil
}
func (e *Engine) encodeState(s *State) ([]byte, error) {
	if e.retention.IsZero() {
		return rlp.Encode(s.data)
	}
	d := s.data
	r := s.recent
	return rlp.Encode(recentStateRLP{d.Version, d.Policy, d.Height, d.Parent, d.Settled, d.Matured, d.Counts, r.From, r.Targets, d.Open})
}
func (e *Engine) decodeState(raw []byte) (*State, error) {
	if e.retention.IsZero() {
		var d stateRLP
		if err := rlp.DecodeStrict(raw, &d); err != nil {
			return nil, err
		}
		return &State{data: d}, nil
	}
	var d recentStateRLP
	if err := rlp.DecodeStrict(raw, &d); err != nil {
		return nil, err
	}
	return &State{data: stateRLP{Version: d.Version, Policy: d.Policy, Height: d.Height, Parent: d.Parent, Settled: d.Settled, Matured: d.Matured, Counts: d.Counts, Open: d.Open}, recent: &recentState{From: d.From, Targets: d.Recent}}, nil
}
