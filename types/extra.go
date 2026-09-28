// Copyright 2017 The go-ethereum Authors
// Copyright 2024 The go-wemix-wbft Authors
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
// The SealerSet methods and the EpochInfo accessors are adapted from
// core/types/istanbul.go of go-stablenet (commit 740526d03), which is derived
// from quorum/core/types/istanbul.go.

package types

import "math/big"

// SealerSet is the bitmap of sealer indices of an aggregated seal: index i is
// bit i mod 8 (counting from the least significant bit) of byte i div 8.
//
// Spec: WBFT-ENC-041
type SealerSet []byte

// SetSealer sets index i, extending the bitmap by whole zero bytes when
// needed. Setting an index twice has no further effect.
func (s *SealerSet) SetSealer(index uint32) {
	byteIndex := int(index / 8)
	if len(*s) <= byteIndex {
		*s = append(*s, make([]byte, byteIndex+1-len(*s))...)
	}
	(*s)[byteIndex] |= 1 << (index % 8)
}

// IsSealer reports whether index i is set.
func (s SealerSet) IsSealer(index uint32) bool {
	byteIndex := int(index / 8)
	if byteIndex >= len(s) {
		return false
	}
	return s[byteIndex]&(1<<(index%8)) != 0
}

// Sealers returns the set indices in ascending order. Trailing zero bytes
// name no index.
func (s SealerSet) Sealers() []uint32 {
	sealers := make([]uint32, 0)
	for byteIndex := 0; byteIndex < len(s); byteIndex++ {
		for bitOffset := 0; bitOffset < 8; bitOffset++ {
			if s[byteIndex]&(1<<bitOffset) != 0 {
				sealers = append(sealers, uint32(byteIndex*8+bitOffset))
			}
		}
	}
	return sealers
}

// AggregatedSeal is the BLS aggregate of the seals of a set of validators
// together with the bitmap of their indices.
//
// Spec: WBFT-ENC-040
type AggregatedSeal struct {
	Sealers   SealerSet
	Signature []byte // 96-byte compressed G2 point when well formed
}

// Copy returns a deep copy of a.
func (a *AggregatedSeal) Copy() *AggregatedSeal {
	if a == nil {
		return nil
	}
	return &AggregatedSeal{
		Sealers:   append(SealerSet(nil), a.Sealers...),
		Signature: append([]byte(nil), a.Signature...),
	}
}

// Candidate is one candidate of an EpochInfo with its diligence in units of
// 10^-6.
type Candidate struct {
	Addr      Address
	Diligence uint64
}

// EpochInfo is the information an epoch block records for the next epoch:
// the candidates, the validators as indices into the candidates, and the BLS
// public key of each validator.
//
// Spec: WBFT-TYPE-021
type EpochInfo struct {
	Candidates    []Candidate
	Validators    []uint32
	BLSPublicKeys [][]byte
}

// Candidate returns the address of candidate i, or the zero address when i
// is not a valid index.
//
// Spec: WBFT-VAL-007
func (e *EpochInfo) Candidate(i uint32) Address {
	if e == nil || int(i) >= len(e.Candidates) {
		return Address{}
	}
	return e.Candidates[i].Addr
}

// ValidatorAddresses returns the address of every validator in the order of
// Validators.
func (e *EpochInfo) ValidatorAddresses() []Address {
	if e == nil {
		return nil
	}
	out := make([]Address, len(e.Validators))
	for i, v := range e.Validators {
		out[i] = e.Candidate(v)
	}
	return out
}

// Copy returns a deep copy of e.
func (e *EpochInfo) Copy() *EpochInfo {
	if e == nil {
		return nil
	}
	c := &EpochInfo{
		Candidates: append([]Candidate(nil), e.Candidates...),
		Validators: append([]uint32(nil), e.Validators...),
	}
	if e.BLSPublicKeys != nil {
		c.BLSPublicKeys = make([][]byte, len(e.BLSPublicKeys))
		for i, k := range e.BLSPublicKeys {
			c.BLSPublicKeys[i] = append([]byte(nil), k...)
		}
	}
	return c
}

// WBFTExtra is the ten consensus fields carried in Header.Extra. Absent seals
// and EpochInfo are nil. A decoded GasTip is never nil: an empty item decodes
// to 0.
//
// Spec: WBFT-ENC-020
type WBFTExtra struct {
	VanityData        []byte
	RandaoReveal      []byte
	PrevRound         uint32
	PrevPreparedSeal  *AggregatedSeal
	PrevCommittedSeal *AggregatedSeal
	Round             uint32
	PreparedSeal      *AggregatedSeal
	CommittedSeal     *AggregatedSeal
	GasTip            *big.Int
	EpochInfo         *EpochInfo
}

// SealEntry is one individual seal and the index of its sealer in the
// validator set of the sealed height.
type SealEntry struct {
	Sealer uint32
	Seal   []byte
}
