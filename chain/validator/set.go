// Copyright 2025 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// Proposer selection follows consensus/wbft/validator/default.go of
// go-stablenet (commit 740526d03), which is derived from
// quorum/consensus/istanbul/validator/default.go.

package validator

import (
	"bytes"
	"errors"

	"github.com/0xmhha/wbft/types"
)

// Errors of set construction and lookup.
var (
	ErrKeysShort        = errors.New("validator: fewer BLS public keys than validators")
	ErrNoProposerPolicy = errors.New("validator: no proposer policy configured")
	ErrUnknownAncestor  = errors.New("unknown ancestor")
	ErrEpochInfoNil     = errors.New("WBFT: epochInfo is nil")
)

// Member is one entry of a validator set: an address and its BLS public key
// as recorded (the key is not decoded here; a key that does not decode makes
// every seal check that uses it fail).
type Member struct {
	Addr         types.Address
	BLSPublicKey []byte
}

// Set is an ordered validator set with the proposer policy of its height.
// The order is the order of EpochInfo.Validators (or of anzeon.init for
// height 0); no sorting is applied. A Set is immutable.
//
// Spec: WBFT-VAL-006
type Set struct {
	members []Member
	policy  types.ProposerPolicy
}

// NewSet builds a set from addresses and keys at the same positions. Keys
// beyond the addresses are ignored; fewer keys than addresses is an error.
func NewSet(addrs []types.Address, keys [][]byte, policy types.ProposerPolicy) (*Set, error) {
	if len(keys) < len(addrs) {
		return nil, ErrKeysShort
	}
	s := &Set{members: make([]Member, len(addrs)), policy: policy}
	for i, a := range addrs {
		s.members[i] = Member{Addr: a, BLSPublicKey: keys[i]}
	}
	return s, nil
}

// NewSetFromEpochInfo builds the set (candidates[validators[i]].addr,
// bls_public_keys[i]) for i in the order of ei.Validators. An index outside
// the candidates maps to the zero address.
//
// Spec: WBFT-TYPE-021, WBFT-VAL-007
func NewSetFromEpochInfo(ei *types.EpochInfo, policy types.ProposerPolicy) (*Set, error) {
	return NewSet(ei.ValidatorAddresses(), ei.BLSPublicKeys, policy)
}

// Len returns the number of members.
func (s *Set) Len() int { return len(s.members) }

// At returns member i. It panics when i is out of range.
func (s *Set) At(i int) Member { return s.members[i] }

// Get returns member i and true, or false when i is out of range.
func (s *Set) Get(i uint64) (Member, bool) {
	if i < uint64(len(s.members)) {
		return s.members[i], true
	}
	return Member{}, false
}

// Addresses returns the member addresses in order.
func (s *Set) Addresses() []types.Address {
	out := make([]types.Address, len(s.members))
	for i, m := range s.members {
		out[i] = m.Addr
	}
	return out
}

// Policy returns the proposer policy of the set.
func (s *Set) Policy() types.ProposerPolicy { return s.policy }

// IndexOf returns the index of the first member with address a.
func (s *Set) IndexOf(a types.Address) (int, bool) {
	for i, m := range s.members {
		if m.Addr == a {
			return i, true
		}
	}
	return -1, false
}

// Contains reports whether a is a member.
func (s *Set) Contains(a types.Address) bool {
	_, ok := s.IndexOf(a)
	return ok
}

// F returns FValue(Len()).
func (s *Set) F() float64 { return FValue(len(s.members)) }

// Quorum returns QuorumSize(Len()).
func (s *Set) Quorum() int { return QuorumSize(len(s.members)) }

// CalcProposer returns the index of the proposer for round (the low 64 bits
// of the round) after lastProposer, or -1 for an empty set. With a zero last
// proposer the seed is the round; otherwise it is the index of the first
// member with that address (0 when none) plus the round, plus one for every
// policy but Sticky. The seed is a uint64 and wraps modulo 2^64.
//
// Spec: WBFT-PROP-001, WBFT-PROP-003, WBFT-PROP-004, WBFT-PROP-006
func (s *Set) CalcProposer(lastProposer types.Address, round uint64) int {
	size := uint64(len(s.members))
	if size == 0 {
		return -1
	}
	var seed uint64
	if lastProposer == (types.Address{}) {
		seed = round
	} else {
		offset := 0
		if i, ok := s.IndexOf(lastProposer); ok {
			offset = i
		}
		seed = uint64(offset) + round
		if !s.policy.IsSticky() {
			seed++
		}
	}
	return int(seed % size)
}

// IsProposer reports whether addr is the proposer at index proposer (-1 for
// none). The reference compares the proposer entry with the first entry of
// addr for deep equality: both absent is true; otherwise the addresses and
// the BLS key bytes must be equal.
//
// Spec: WBFT-PROP-007
func (s *Set) IsProposer(proposer int, addr types.Address) bool {
	var p, c *Member
	if proposer >= 0 && proposer < len(s.members) {
		p = &s.members[proposer]
	}
	if i, ok := s.IndexOf(addr); ok {
		c = &s.members[i]
	}
	if p == nil || c == nil {
		return p == nil && c == nil
	}
	return p.Addr == c.Addr && deepEqualBytes(p.BLSPublicKey, c.BLSPublicKey)
}

// deepEqualBytes is reflect.DeepEqual on two byte slices: a nil slice equals
// only a nil slice.
func deepEqualBytes(a, b []byte) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return bytes.Equal(a, b)
}
