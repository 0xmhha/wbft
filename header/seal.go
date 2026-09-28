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
// The seal operations follow CommitHeader, aggregateSeal, mergeSeals,
// verifyAggregatedSeal, CalculateRandaoMix, getExtra and
// ApplyHeaderWBFTExtra of consensus/wbft/engine of go-stablenet (commit
// 740526d03), which are derived from quorum/consensus/istanbul/qbft/engine.

package header

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// startExtra is getExtra: a builder extra shorter than 32 bytes becomes the
// zero-padded vanity of a new, otherwise empty extra; a longer one is decoded
// as a complete WBFTExtra.
//
// Spec: WBFT-HDR-016, WBFT-ENC-031
func startExtra(h *types.Header) (*types.WBFTExtra, error) {
	if len(h.Extra) < types.ExtraVanity {
		vanity := make([]byte, types.ExtraVanity)
		copy(vanity, h.Extra)
		return &types.WBFTExtra{VanityData: vanity, RandaoReveal: []byte{}}, nil
	}
	return codec.DecodeExtra(h)
}

// applyExtra starts the extra of h, applies fns in order and writes the
// result back into h.
func applyExtra(h *types.Header, fns ...func(*types.WBFTExtra) error) (*types.WBFTExtra, error) {
	x, err := startExtra(h)
	if err != nil {
		return nil, err
	}
	for _, f := range fns {
		if err := f(x); err != nil {
			return nil, err
		}
	}
	return x, codec.SetExtra(h, x)
}

// aggregateSeals sets the bit of every sealer and aggregates the seals. A
// seal whose length is not 96 bytes fails with ErrInvalidSeal; a seal that
// does not decode fails the aggregation. A sealer given twice sets its bit
// once and adds its seal twice, so the aggregate does not verify.
//
// Spec: WBFT-CRYPTO-031, WBFT-PARAM-011
func aggregateSeals(seals []types.SealEntry) (*types.AggregatedSeal, error) {
	sigs := make([][]byte, 0, len(seals))
	var sealers types.SealerSet
	for _, s := range seals {
		if len(s.Seal) != types.SealLength {
			return nil, ErrInvalidSeal
		}
		sealers.SetSealer(s.Sealer)
		sigs = append(sigs, s.Seal)
	}
	agg, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, err
	}
	return &types.AggregatedSeal{Sealers: sealers, Signature: agg.Bytes()}, nil
}

// CommitHeader writes the aggregated prepared and committed seals and the
// round (its low 32 bits) into the extra of a copy of b's header. The block
// hash does not change. An empty list fails with ErrInvalidPreparedSeals or
// ErrInvalidCommittedSeals; the checks run in the order prepared list,
// prepared seals, committed list, committed seals.
//
// The seals written are those this node collected: the values of Round,
// PreparedSeal and CommittedSeal are node-local.
//
// Spec: WBFT-HDR-050, WBFT-HDR-051, WBFT-HDR-052, WBFT-HDR-053
func CommitHeader(b *types.Block, round types.Round, prepared, committed []types.SealEntry) (*types.Block, error) {
	h := b.Header.Copy()
	_, err := applyExtra(h,
		func(x *types.WBFTExtra) error {
			if len(prepared) == 0 {
				return ErrInvalidPreparedSeals
			}
			agg, err := aggregateSeals(prepared)
			if err != nil {
				return err
			}
			x.PreparedSeal = agg
			return nil
		},
		func(x *types.WBFTExtra) error {
			if len(committed) == 0 {
				return ErrInvalidCommittedSeals
			}
			agg, err := aggregateSeals(committed)
			if err != nil {
				return err
			}
			x.CommittedSeal = agg
			return nil
		},
		func(x *types.WBFTExtra) error {
			x.Round = round.RefLow32() //wbft:low64 HH-74
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return &types.Block{Header: h, Body: b.Body}, nil
}

// MergeSeals adds extra seals to an aggregated seal: an index already in the
// bitmap is skipped, every new index is set and its seal aggregated with the
// existing aggregate. If the aggregation fails for any input, the input seal
// is returned unchanged. The result is not verified.
//
// Spec: WBFT-HDR-034, WBFT-HDR-036
func MergeSeals(agg *types.AggregatedSeal, extra []types.SealEntry) *types.AggregatedSeal {
	if len(extra) == 0 {
		return agg
	}
	sigs := [][]byte{agg.Signature}
	sealers := append(types.SealerSet(make([]byte, 0, len(agg.Sealers))), agg.Sealers...)
	for _, e := range extra {
		if sealers.IsSealer(e.Sealer) {
			continue
		}
		sealers.SetSealer(e.Sealer)
		sigs = append(sigs, e.Seal)
	}
	sum, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return agg
	}
	return &types.AggregatedSeal{Sealers: sealers, Signature: sum.Bytes()}
}

// VerifyAggregatedSeal checks an aggregated seal of header h in the order of
// the reference: at least a quorum of distinct sealer indices, every index
// inside vs, the aggregate of the sealers' public keys (each decoded; a sum
// equal to the point at infinity never verifies), the signature decoding, and
// the BLS verification over seal_data(h, round, t).
//
// Spec: WBFT-CRYPTO-030, WBFT-HDR-100, WBFT-HDR-101, WBFT-CRYPTO-055
func VerifyAggregatedSeal(vs *validator.Set, h *types.Header, round uint32, agg *types.AggregatedSeal, t types.SealType) error {
	sealers := agg.Sealers.Sealers()
	if len(sealers) < vs.Quorum() {
		return ErrLackOfSealCount
	}
	keys := make([][]byte, 0, len(sealers))
	for _, s := range sealers {
		m, ok := vs.Get(uint64(s))
		if !ok {
			return ErrSealerNotValidator
		}
		keys = append(keys, m.BLSPublicKey)
	}
	msg := codec.SealData(h, round, t)
	apk, err := bls.AggregatePublicKeys(keys)
	if err != nil {
		return err
	}
	sig, err := bls.DecodeSignature(agg.Signature)
	if err != nil {
		return err
	}
	if !bls.Verify(apk, msg, sig) {
		return ErrInvalidSeal
	}
	return nil
}

// RandaoMix is randao_mix(parentMix, reveal): the bytewise XOR of parentMix
// and keccak256(reveal), 32 bytes with leading zeros kept.
//
// Spec: WBFT-CRYPTO-053
func RandaoMix(parentMix types.Hash, reveal []byte) types.Hash {
	k := keccak.Sum256(reveal)
	var out types.Hash
	for i := range out {
		out[i] = parentMix[i] ^ k[i]
	}
	return out
}
