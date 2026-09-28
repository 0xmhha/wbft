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
// The wire structures of this file follow the RLP methods of WBFTExtra,
// WBFTAggregatedSeal, EpochInfo and Candidate in core/types/istanbul.go of
// go-stablenet (commit 740526d03), so that the go-ethereum RLP package
// applies the same field types and "nil" tags.

package codec

import (
	"errors"
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

// ErrInvalidExtraDataFormat is returned when Header.Extra does not decode as
// WBFTExtra.
var ErrInvalidExtraDataFormat = errors.New("invalid extra data format")

// aggSealRLP is the two-item list [sealers, signature].
type aggSealRLP struct {
	Sealers   []byte
	Signature []byte
}

// candidateRLP is the two-item list [addr, diligence].
type candidateRLP struct {
	Addr      types.Address
	Diligence uint64
}

// epochInfoRLP is the three-item list [candidates, validators, keys]. An
// element of Candidates that is an empty list is decoded as a candidate and
// fails.
type epochInfoRLP struct {
	Candidates    []*candidateRLP
	Validators    []uint32
	BLSPublicKeys [][]byte
}

// extraRLP is the ten-item WBFTExtra list. The "nil" tags make an empty list
// decode as an absent seal or EpochInfo and reject an empty string there; a
// big integer is never absent after decoding (an empty string is 0).
type extraRLP struct {
	VanityData        []byte
	RandaoReveal      []byte
	PrevRound         uint32
	PrevPreparedSeal  *aggSealRLP `rlp:"nil"`
	PrevCommittedSeal *aggSealRLP `rlp:"nil"`
	Round             uint32
	PreparedSeal      *aggSealRLP   `rlp:"nil"`
	CommittedSeal     *aggSealRLP   `rlp:"nil"`
	GasTip            *big.Int      `rlp:"nil"`
	EpochInfo         *epochInfoRLP `rlp:"nil"`
}

func sealToRLP(s *types.AggregatedSeal) *aggSealRLP {
	if s == nil {
		return nil
	}
	return &aggSealRLP{Sealers: s.Sealers, Signature: s.Signature}
}

func sealFromRLP(s *aggSealRLP) *types.AggregatedSeal {
	if s == nil {
		return nil
	}
	return &types.AggregatedSeal{Sealers: types.SealerSet(s.Sealers), Signature: s.Signature}
}

func epochToRLP(e *types.EpochInfo) *epochInfoRLP {
	if e == nil {
		return nil
	}
	out := &epochInfoRLP{Validators: e.Validators, BLSPublicKeys: e.BLSPublicKeys}
	if e.Candidates != nil {
		out.Candidates = make([]*candidateRLP, len(e.Candidates))
		for i, c := range e.Candidates {
			out.Candidates[i] = &candidateRLP{Addr: c.Addr, Diligence: c.Diligence}
		}
	}
	return out
}

func epochFromRLP(e *epochInfoRLP) *types.EpochInfo {
	if e == nil {
		return nil
	}
	out := &types.EpochInfo{Validators: e.Validators, BLSPublicKeys: e.BLSPublicKeys}
	if e.Candidates != nil {
		out.Candidates = make([]types.Candidate, len(e.Candidates))
		for i, c := range e.Candidates {
			out.Candidates[i] = types.Candidate{Addr: c.Addr, Diligence: c.Diligence}
		}
	}
	return out
}

// EncodeExtra returns the RLP encoding of x: the ten-item list with absent
// seals and EpochInfo as 0xc0 and an absent gas tip as 0x80.
//
// Spec: WBFT-ENC-020, WBFT-ENC-006, WBFT-ENC-032, WBFT-ENC-033, WBFT-ENC-040, WBFT-ENC-050
func EncodeExtra(x *types.WBFTExtra) ([]byte, error) {
	w := extraRLP{
		VanityData:        x.VanityData,
		RandaoReveal:      x.RandaoReveal,
		PrevRound:         x.PrevRound,
		PrevPreparedSeal:  sealToRLP(x.PrevPreparedSeal),
		PrevCommittedSeal: sealToRLP(x.PrevCommittedSeal),
		Round:             x.Round,
		PreparedSeal:      sealToRLP(x.PreparedSeal),
		CommittedSeal:     sealToRLP(x.CommittedSeal),
		GasTip:            x.GasTip,
		EpochInfo:         epochToRLP(x.EpochInfo),
	}
	return rlp.Encode(&w)
}

// DecodeExtraBytes decodes b as one WBFTExtra list with the rules of A-03
// sections 2 to 4: exactly ten items, canonical items, no trailing bytes,
// 0xc0 for an absent seal or EpochInfo (0x80 is rejected there), and 0x80
// for a gas tip of 0. Every accepted input re-encodes to itself.
//
// Any length of vanity_data, randao_reveal, sealers, signature and key is
// accepted here; a present seal with an empty signature differs from an
// absent one.
//
// Spec: WBFT-ENC-021, WBFT-ENC-022, WBFT-ENC-007, WBFT-ENC-008, WBFT-ENC-030, WBFT-ENC-043, WBFT-ENC-051
func DecodeExtraBytes(b []byte) (*types.WBFTExtra, error) {
	var w extraRLP
	if err := rlp.DecodeStrict(b, &w); err != nil {
		return nil, err
	}
	return &types.WBFTExtra{
		VanityData:        w.VanityData,
		RandaoReveal:      w.RandaoReveal,
		PrevRound:         w.PrevRound,
		PrevPreparedSeal:  sealFromRLP(w.PrevPreparedSeal),
		PrevCommittedSeal: sealFromRLP(w.PrevCommittedSeal),
		Round:             w.Round,
		PreparedSeal:      sealFromRLP(w.PreparedSeal),
		CommittedSeal:     sealFromRLP(w.CommittedSeal),
		GasTip:            w.GasTip,
		EpochInfo:         epochFromRLP(w.EpochInfo),
	}, nil
}

// DecodeExtra decodes the extra data of h. The error is the decoding error;
// header verification reports any failure as ErrInvalidExtraDataFormat.
func DecodeExtra(h *types.Header) (*types.WBFTExtra, error) {
	return DecodeExtraBytes(h.Extra)
}

// SetExtra encodes x into h.Extra.
func SetExtra(h *types.Header, x *types.WBFTExtra) error {
	b, err := EncodeExtra(x)
	if err != nil {
		return err
	}
	h.Extra = b
	return nil
}
