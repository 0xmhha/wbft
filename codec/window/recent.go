package window

import (
	"bytes"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
	"math/big"
)

type recentSettlementRLP struct {
	Version  uint64
	Previous *big.Int
	Through  *big.Int
	From     *big.Int
	Rows     []Counts
}
type recentObservationRLP struct {
	Version    uint64
	Policy     types.Hash
	Parent     types.Hash
	Result     types.Hash
	Settlement *recentSettlementRLP `rlp:"nil"`
}
type recentExtraRLP struct {
	Version     uint64
	Legacy      rlp.RawValue
	Proofs      []proofRLP
	Observation recentObservationRLP
}

func observationVersion(raw []byte, l Limits) (uint64, error) {
	if err := preflight(raw, l); err != nil {
		return 0, err
	}
	outer, err := rlp.ListItems(raw)
	if err != nil {
		return 0, ErrFormat
	}
	obs, err := rlp.ListItems(outer[3])
	if err != nil {
		return 0, ErrFormat
	}
	var version uint64
	if rlp.DecodeStrict(obs[0], &version) != nil || (version != 1 && version != 2) {
		return 0, ErrFormat
	}
	return version, nil
}
func validateRecent(w *recentExtraRLP, l Limits) error {
	if w.Observation.Version != 2 {
		return ErrFormat
	}
	// The common proof and legacy checks are identical across observation modes.
	common := &extraRLP{Version: w.Version, Legacy: w.Legacy, Proofs: w.Proofs, Observation: observationRLP{Version: 1}}
	if err := validate(common, l); err != nil {
		return err
	}
	if s := w.Observation.Settlement; s != nil {
		if s.Version != 2 || s.Previous == nil || s.Through == nil || s.From == nil || s.Previous.Sign() < 0 || s.Through.Cmp(s.Previous) < 0 || s.From.Sign() <= 0 {
			return ErrFormat
		}
		width := new(big.Int).Sub(new(big.Int).Add(s.Through, big.NewInt(1)), s.From)
		if width.Sign() < 0 || (width.Sign() == 0 && len(s.Rows) != 0) {
			return ErrFormat
		}
		if uint64(len(s.Rows)) > uint64(l.SettlementRows) {
			return ErrLimit
		}
		for i, r := range s.Rows {
			if !validCounts(r) || r.EligiblePrepare.Sign() <= 0 || r.EligiblePrepare.Cmp(r.EligibleCommit) != 0 || r.EligiblePrepare.Cmp(width) > 0 || (i > 0 && bytes.Compare(s.Rows[i-1].Address[:], r.Address[:]) >= 0) {
				return ErrFormat
			}
		}
	}
	return nil
}
func encodeRecent(x *Extra, l Limits) ([]byte, error) {
	if !l.valid() {
		return nil, ErrLimit
	}
	if x == nil || x.Legacy == nil || x.Observation.Version != 2 || x.Observation.Settlement != nil {
		return nil, ErrFormat
	}
	legacy, err := codec.EncodeExtra(x.Legacy)
	if err != nil {
		return nil, err
	}
	w := &recentExtraRLP{Version: 2, Legacy: legacy, Observation: recentObservationRLP{Version: 2, Policy: x.Observation.PolicyDigest, Parent: x.Observation.ParentStateRoot, Result: x.Observation.ResultStateRoot}}
	for _, p := range x.Proofs {
		w.Proofs = append(w.Proofs, proofRLP{p.Height.Big(), p.Hash, p.Round, p.Authority, uint8(p.Phase), p.Bitmap, p.Signature})
	}
	if s := x.Observation.Recent; s != nil {
		w.Observation.Settlement = &recentSettlementRLP{2, s.Previous.Big(), s.Through.Big(), s.From.Big(), s.Rows}
	}
	if err = validateRecent(w, l); err != nil {
		return nil, err
	}
	raw, err := rlp.Encode(w)
	if err != nil {
		return nil, err
	}
	if uint64(len(raw)) > l.ExtraBytes {
		return nil, ErrLimit
	}
	return raw, nil
}
func decodeRecent(raw []byte, l Limits) (*Extra, error) {
	var w recentExtraRLP
	if err := rlp.DecodeStrict(raw, &w); err != nil {
		return nil, ErrFormat
	}
	if err := validateRecent(&w, l); err != nil {
		return nil, err
	}
	legacy, err := codec.DecodeExtraBytes(w.Legacy)
	if err != nil {
		return nil, err
	}
	x := &Extra{Legacy: legacy, Observation: Observation{Version: 2, PolicyDigest: w.Observation.Policy, ParentStateRoot: w.Observation.Parent, ResultStateRoot: w.Observation.Result}}
	for _, p := range w.Proofs {
		x.Proofs = append(x.Proofs, Proof{types.MustHeightFromBig(p.Height), p.Hash, p.Round, p.Authority, types.SealType(p.Phase), p.Bitmap, p.Signature})
	}
	if s := w.Observation.Settlement; s != nil {
		x.Observation.Recent = &RecentSettlement{types.MustHeightFromBig(s.Previous), types.MustHeightFromBig(s.Through), types.MustHeightFromBig(s.From), s.Rows}
	}
	return x, nil
}
