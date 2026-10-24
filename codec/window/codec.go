package window

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

var (
	ErrFormat = errors.New("window: invalid observation format")
	ErrLimit  = errors.New("window: structural limit")
)

type proofRLP struct {
	Height    *big.Int
	Hash      types.Hash
	Round     uint32
	Authority types.Hash
	Phase     uint8
	Bitmap    []byte
	Signature []byte
}
type settlementRLP struct {
	Version  uint64
	Previous *big.Int
	Through  *big.Int
	Rows     []Counts
}
type observationRLP struct {
	Version    uint64
	Policy     types.Hash
	Parent     types.Hash
	Result     types.Hash
	Settlement *settlementRLP `rlp:"nil"`
}
type extraRLP struct {
	Version     uint64
	Legacy      rlp.RawValue
	Proofs      []proofRLP
	Observation observationRLP
}

func (l Limits) valid() bool {
	return l.ExtraBytes > 0 && l.Proofs > 0 && l.SettlementRows > 0 && l.Validators > 0
}

func validCounts(c Counts) bool {
	for _, n := range []*big.Int{c.EligiblePrepare, c.EligibleCommit, c.ObservedPrepare, c.ObservedCommit} {
		if n == nil || n.Sign() < 0 {
			return false
		}
	}
	return c.ObservedPrepare.Cmp(c.EligiblePrepare) <= 0 && c.ObservedCommit.Cmp(c.EligibleCommit) <= 0
}

func validate(w *extraRLP, l Limits) error {
	if w.Version != 2 || w.Observation.Version != 1 {
		return ErrFormat
	}
	if _, err := codec.DecodeExtraBytes(w.Legacy); err != nil {
		return fmt.Errorf("%w: legacy: %v", ErrFormat, err)
	}
	if uint64(len(w.Proofs)) > uint64(l.Proofs) {
		return ErrLimit
	}
	for i, p := range w.Proofs {
		if p.Height == nil || p.Height.Sign() < 0 || (p.Phase != uint8(types.PrepareSeal) && p.Phase != uint8(types.CommitSeal)) || len(p.Signature) != 96 || len(p.Bitmap) == 0 || p.Bitmap[len(p.Bitmap)-1] == 0 {
			return ErrFormat
		}
		if uint64(len(p.Bitmap)) > (uint64(l.Validators)+7)/8 {
			return ErrLimit
		}
		for _, index := range types.SealerSet(p.Bitmap).Sealers() {
			if index >= l.Validators {
				return ErrLimit
			}
		}
		if i > 0 {
			previous := w.Proofs[i-1]
			cmp := previous.Height.Cmp(p.Height)
			if cmp > 0 || (cmp == 0 && previous.Phase >= p.Phase) {
				return ErrFormat
			}
		}
	}
	if s := w.Observation.Settlement; s != nil {
		if s.Version != 1 || s.Previous == nil || s.Through == nil || s.Previous.Sign() < 0 || s.Through.Cmp(s.Previous) < 0 {
			return ErrFormat
		}
		if uint64(len(s.Rows)) > uint64(l.SettlementRows) {
			return ErrLimit
		}
		if s.Previous.Cmp(s.Through) == 0 && len(s.Rows) != 0 {
			return ErrFormat
		}
		for i, r := range s.Rows {
			if !validCounts(r) || (i > 0 && bytes.Compare(s.Rows[i-1].Address[:], r.Address[:]) >= 0) {
				return ErrFormat
			}
		}
	}
	return nil
}

// preflight bounds the encoded envelope and list counts before reflection
// decoding allocates proof and settlement-row structures.
func preflight(raw []byte, l Limits) error {
	if !l.valid() || uint64(len(raw)) > l.ExtraBytes {
		return ErrLimit
	}
	items, err := rlp.ListItems(raw)
	if err != nil || len(items) != 4 {
		return ErrFormat
	}
	proofs, err := rlp.ListItems(items[2])
	if err != nil {
		return ErrFormat
	}
	if uint64(len(proofs)) > uint64(l.Proofs) {
		return ErrLimit
	}
	obs, err := rlp.ListItems(items[3])
	if err != nil || len(obs) != 5 {
		return ErrFormat
	}
	if !bytes.Equal(obs[4], rlp.EmptyList) {
		s, err := rlp.ListItems(obs[4])
		if err != nil || len(s) != 4 {
			return ErrFormat
		}
		rows, err := rlp.ListItems(s[3])
		if err != nil {
			return ErrFormat
		}
		if uint64(len(rows)) > uint64(l.SettlementRows) {
			return ErrLimit
		}
	}
	return nil
}

func wire(x *Extra) (*extraRLP, error) {
	if x == nil || x.Legacy == nil {
		return nil, ErrFormat
	}
	legacy, err := codec.EncodeExtra(x.Legacy)
	if err != nil {
		return nil, err
	}
	w := &extraRLP{Version: 2, Legacy: legacy, Observation: observationRLP{Version: 1, Policy: x.Observation.PolicyDigest, Parent: x.Observation.ParentStateRoot, Result: x.Observation.ResultStateRoot}}
	for _, p := range x.Proofs {
		w.Proofs = append(w.Proofs, proofRLP{p.Height.Big(), p.Hash, p.Round, p.Authority, uint8(p.Phase), p.Bitmap, p.Signature})
	}
	if s := x.Observation.Settlement; s != nil {
		w.Observation.Settlement = &settlementRLP{1, s.Previous.Big(), s.Through.Big(), s.Rows}
	}
	return w, nil
}

// Encode returns the canonical explicit envelope within the supplied limits.
// No chain rule, state-root transition or cryptographic verification is applied.
func Encode(x *Extra, l Limits) ([]byte, error) {
	if !l.valid() {
		return nil, ErrLimit
	}
	w, err := wire(x)
	if err != nil {
		return nil, err
	}
	if err = validate(w, l); err != nil {
		return nil, err
	}
	b, err := rlp.Encode(w)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > l.ExtraBytes {
		return nil, ErrLimit
	}
	return b, nil
}

// Decode accepts only a canonical explicit envelope. It does not fall back to
// the legacy format or treat an unknown version as an empty observation.
func Decode(raw []byte, l Limits) (*Extra, error) {
	if err := preflight(raw, l); err != nil {
		return nil, err
	}
	var w extraRLP
	if err := rlp.DecodeStrict(raw, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if err := validate(&w, l); err != nil {
		return nil, err
	}
	legacy, err := codec.DecodeExtraBytes(w.Legacy)
	if err != nil {
		return nil, err
	}
	x := &Extra{Legacy: legacy, Observation: Observation{PolicyDigest: w.Observation.Policy, ParentStateRoot: w.Observation.Parent, ResultStateRoot: w.Observation.Result}}
	for _, p := range w.Proofs {
		x.Proofs = append(x.Proofs, Proof{types.MustHeightFromBig(p.Height), p.Hash, p.Round, p.Authority, types.SealType(p.Phase), p.Bitmap, p.Signature})
	}
	if s := w.Observation.Settlement; s != nil {
		x.Observation.Settlement = &Settlement{types.MustHeightFromBig(s.Previous), types.MustHeightFromBig(s.Through), s.Rows}
	}
	return x, nil
}
