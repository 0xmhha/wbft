package source

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"sync"

	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// Errors of snapshot construction.
var (
	ErrNilGasTip           = errors.New("source: snapshot gas tip is nil")
	ErrBlacklistedNotScope = errors.New("source: blacklisted address outside the scope")
)

// AuthoritySnapshot is the authority information derived from the state after
// executing one block: the gas tip its child must carry, the validators that
// may propose the child (the scope) and those of them that are blacklisted in
// that state. The application builds one per executed block; it is immutable.
type AuthoritySnapshot struct {
	number types.Height
	hash   types.Hash
	gasTip *uint256.Int

	candidates  []types.CandidateEntry
	scope       []types.Address // sorted
	blacklisted []types.Address // sorted, subset of scope
}

// NewAuthoritySnapshot freezes a snapshot. It requires a non-nil gas tip and
// blacklisted to be a subset of scope. The inputs are copied.
func NewAuthoritySnapshot(number types.Height, hash types.Hash, gasTip *uint256.Int,
	scope, blacklisted []types.Address, candidates []types.CandidateEntry) (*AuthoritySnapshot, error) {
	if gasTip == nil {
		return nil, ErrNilGasTip
	}
	s := &AuthoritySnapshot{
		number:      number,
		hash:        hash,
		gasTip:      new(uint256.Int).Set(gasTip),
		scope:       sortedUnique(scope),
		blacklisted: sortedUnique(blacklisted),
	}
	for _, b := range s.blacklisted {
		if _, ok := slices.BinarySearchFunc(s.scope, b, cmpAddr); !ok {
			return nil, ErrBlacklistedNotScope
		}
	}
	for _, c := range candidates {
		s.candidates = append(s.candidates, types.CandidateEntry{Addr: c.Addr, BLSPublicKey: append([]byte(nil), c.BLSPublicKey...)})
	}
	return s, nil
}

func cmpAddr(a, b types.Address) int { return a.Cmp(b) }

func sortedUnique(in []types.Address) []types.Address {
	out := append([]types.Address(nil), in...)
	slices.SortFunc(out, cmpAddr) // addresses are distinct keys after Compact
	return slices.Compact(out)
}

// Number returns the number of the executed block.
func (s *AuthoritySnapshot) Number() types.Height { return s.number }

// Hash returns the hash of the executed block.
func (s *AuthoritySnapshot) Hash() types.Hash { return s.hash }

// GasTip returns a copy of the gas tip the child header must carry.
func (s *AuthoritySnapshot) GasTip() *uint256.Int { return new(uint256.Int).Set(s.gasTip) }

// Scope returns a copy of the scope, sorted.
func (s *AuthoritySnapshot) Scope() []types.Address { return append([]types.Address(nil), s.scope...) }

// Candidates returns a copy of the candidates (set only for epoch blocks).
func (s *AuthoritySnapshot) Candidates() []types.CandidateEntry {
	out := make([]types.CandidateEntry, len(s.candidates))
	for i, c := range s.candidates {
		out[i] = types.CandidateEntry{Addr: c.Addr, BLSPublicKey: append([]byte(nil), c.BLSPublicKey...)}
	}
	return out
}

// Eligibility answers whether addr may propose the child of this block:
// Ineligible when it is blacklisted, Eligible when it is in the scope, and
// Unknown outside the scope.
func (s *AuthoritySnapshot) Eligibility(addr types.Address) types.Eligibility {
	if _, ok := slices.BinarySearchFunc(s.blacklisted, addr, cmpAddr); ok {
		return types.Ineligible
	}
	if _, ok := slices.BinarySearchFunc(s.scope, addr, cmpAddr); ok {
		return types.Eligible
	}
	return types.Unknown
}

// AuthoritySource is implemented by the execution side of a node.
type AuthoritySource interface {
	// CandidatesAfterExecution returns the candidates of the epoch block
	// whose execution is in progress in ctx.
	CandidatesAfterExecution(ctx context.Context) ([]types.CandidateEntry, error)
	// Snapshot returns the snapshot of the executed block with that hash.
	Snapshot(ctx context.Context, hash types.Hash) (*AuthoritySnapshot, error)
}

// Native marks an AuthoritySource whose origin is a native module.
type Native interface{ NativeAuthority() }

// DefaultCacheSize is the number of blocks the snapshot cache keeps.
const DefaultCacheSize = 256

// Cache keeps the snapshots of the most recently added blocks, keyed by
// block hash. It is safe for concurrent use.
type Cache struct {
	mu    sync.RWMutex
	size  int
	byKey map[types.Hash]*AuthoritySnapshot
	order []types.Hash // insertion order, oldest first
}

// NewCache returns a cache that keeps at most size snapshots (at least 1).
func NewCache(size int) *Cache {
	if size < 1 {
		size = 1
	}
	return &Cache{size: size, byKey: make(map[types.Hash]*AuthoritySnapshot, size)}
}

// Put adds s, replacing a snapshot of the same block and evicting the oldest
// one when the cache is full.
func (c *Cache) Put(s *AuthoritySnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byKey[s.hash]; ok {
		c.byKey[s.hash] = s
		return
	}
	if len(c.order) >= c.size {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.byKey, oldest)
	}
	c.byKey[s.hash] = s
	c.order = append(c.order, s.hash)
}

// Get returns the snapshot of the block with that hash.
func (c *Cache) Get(hash types.Hash) (*AuthoritySnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.byKey[hash]
	return s, ok
}

// Len returns the number of cached snapshots.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.order)
}

// ErrGasTipRange is returned for a gas tip that is negative or does not fit
// in 256 bits.
var ErrGasTipRange = errors.New("source: gas tip outside the 256-bit range")

// GasTipFromBig converts a gas tip in wei to the snapshot representation.
func GasTipFromBig(b *big.Int) (*uint256.Int, error) {
	if b == nil || b.Sign() < 0 {
		return nil, ErrGasTipRange
	}
	v, overflow := uint256.FromBig(b)
	if overflow {
		return nil, ErrGasTipRange
	}
	return v, nil
}
