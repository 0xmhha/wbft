package window

import (
	"bytes"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

func (e *Engine) transition(parent *State, h *types.Header, x *wire.Extra, history History) (*State, *wire.Settlement, *wire.RecentSettlement, error) {
	if h == nil || x == nil || x.Legacy == nil || history == nil || h.Number.Cmp(e.cfg.Activation) < 0 {
		return nil, nil, nil, ErrHistory
	}
	s, err := e.clone(parent)
	if err != nil {
		return nil, nil, nil, err
	}
	if h.Number.Cmp(s.Height().AddUint64(1)) != 0 || h.ParentHash != s.anchor {
		return nil, nil, nil, ErrHistory
	}
	parentHeader, err := history.Header(h.ParentHash, s.Height())
	if err != nil {
		return nil, nil, nil, err
	}
	hash, err := e.hash(parentHeader)
	if err != nil || parentHeader.Number.Cmp(s.Height()) != 0 || hash != h.ParentHash {
		return nil, nil, nil, ErrHistory
	}
	d := &s.data
	d.Height = h.Number.Big()
	d.Parent = h.ParentHash
	var settlement *wire.Settlement
	var recent *wire.RecentSettlement
	if x.Legacy.EpochInfo != nil {
		if e.retention.IsZero() {
			settlement = &wire.Settlement{Previous: types.MustHeightFromBig(d.Settled), Through: types.MustHeightFromBig(d.Matured), Rows: addRows(nil, d.Pending)}
			d.Counts = addRows(d.Counts, d.Pending)
			d.Pending = nil
		} else {
			from := e.windowFrom(types.MustHeightFromBig(d.Matured))
			recent = &wire.RecentSettlement{Previous: types.MustHeightFromBig(d.Settled), Through: types.MustHeightFromBig(d.Matured), From: from, Rows: recentRows(s.recent.Targets)}
			d.Counts = addRows(nil, recent.Rows)
			s.recent.From = from.Big()
		}
		d.Settled = new(big.Int).Set(d.Matured)
	}

	if parentHeader.Number.Cmp(e.cfg.Activation) >= 0 {
		members, err := history.Authority(parentHeader)
		if err != nil {
			return nil, nil, nil, err
		}
		if _, err = wire.AuthorityDigest(members, e.cfg.Codec); err != nil {
			return nil, nil, nil, err
		}
		var indexed []memberRLP
		seen := make(map[types.Address]struct{}, len(members))
		for i, m := range members {
			if _, err = bls.DecodePublicKey(m.Key); err != nil {
				return nil, nil, nil, err
			}
			if _, exists := seen[m.Address]; exists {
				return nil, nil, nil, ErrHistory
			}
			seen[m.Address] = struct{}{}
			indexed = append(indexed, memberRLP{uint64(i), m.Address, append([]byte(nil), m.Key...)})
		}
		d.Open = append(d.Open, targetRLP{Height: parentHeader.Number.Big(), Hash: h.ParentHash, Round: x.Legacy.PrevRound, Members: indexed})
	}
	for _, p := range x.Proofs {
		age, ok := h.Number.Sub(p.Height)
		if !ok || age.IsZero() || age.CmpUint64(e.cfg.Window) > 0 || p.Height.Cmp(e.cfg.Activation) < 0 {
			return nil, nil, nil, ErrProof
		}
		index := -1
		for i, t := range d.Open {
			if t.Height.Cmp(p.Height.Big()) == 0 {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, nil, nil, ErrProof
		}
		t := &d.Open[index]
		var members []wire.Member
		for _, m := range t.Members {
			members = append(members, wire.Member{Address: m.Address, Key: m.Key})
		}
		authority, err := wire.AuthorityDigest(members, e.cfg.Codec)
		if err != nil || p.Hash != t.Hash || p.Round != t.Round || p.Authority != authority {
			return nil, nil, nil, ErrProof
		}
		target, err := history.Header(t.Hash, p.Height)
		if err != nil {
			return nil, nil, nil, err
		}
		targetHash, err := e.hash(target)
		if err != nil || target.Number.Cmp(p.Height) != 0 || targetHash != t.Hash {
			return nil, nil, nil, ErrHistory
		}
		var keys [][]byte
		for _, i := range types.SealerSet(p.Bitmap).Sealers() {
			if uint64(i) >= uint64(len(t.Members)) {
				return nil, nil, nil, ErrProof
			}
			keys = append(keys, t.Members[i].Key)
		}
		pk, err := bls.AggregatePublicKeys(keys)
		if err != nil {
			return nil, nil, nil, err
		}
		sig, err := bls.DecodeSignature(p.Signature)
		if err != nil {
			return nil, nil, nil, err
		}
		msg, err := wire.SealData(target, p.Round, p.Phase, e.cfg.Codec)
		if err != nil || !bls.Verify(pk, msg, sig) {
			return nil, nil, nil, ErrProof
		}
		if p.Phase == types.PrepareSeal {
			t.Prepare = union(t.Prepare, p.Bitmap)
		} else {
			t.Commit = union(t.Commit, p.Bitmap)
		}
	}
	last, ok := h.Number.Sub(types.HeightFromUint64(e.cfg.Window))
	var open []targetRLP
	for _, t := range d.Open {
		if ok && t.Height.Cmp(last.Big()) <= 0 {
			if t.Height.Cmp(new(big.Int).Add(d.Matured, big.NewInt(1))) != 0 {
				return nil, nil, nil, ErrState
			}
			if e.retention.IsZero() {
				d.Pending = addRows(d.Pending, targetCounts(t))
			} else {
				e.retain(s, t)
			}
			d.Matured = new(big.Int).Set(t.Height)
		} else {
			open = append(open, t)
		}
	}
	d.Open = open
	if _, err = e.stateBytes(s); err != nil {
		return nil, nil, nil, err
	}
	return s, settlement, recent, nil
}

// Build adds observations to a legacy-shaped candidate without changing its
// diligence or epoch information. It returns a separate explicit V2 carrier
// and new state. The caller decides whether such a carrier is enabled by its
// chain rules; this method does not publish, sign or submit it.
func (e *Engine) Build(parent *State, candidate *types.Header, proofs []wire.Proof, history History) (*types.Header, *State, error) {
	if candidate == nil {
		return nil, nil, ErrHistory
	}
	legacy, err := codec.DecodeExtra(candidate)
	if err != nil {
		return nil, nil, err
	}
	if legacy.PreparedSeal != nil || legacy.CommittedSeal != nil {
		return nil, nil, ErrState
	}
	parentRoot, err := e.Root(parent)
	if err != nil {
		return nil, nil, err
	}
	x := &wire.Extra{Legacy: legacy, Proofs: proofs}
	if !e.retention.IsZero() {
		x.Observation.Version = 2
	}
	// Roundtrip before cryptographic work validates bounded sorted structures
	// and gives the transition owned copies of every caller-provided slice.
	raw, err := wire.Encode(x, e.cfg.Codec)
	if err != nil {
		return nil, nil, err
	}
	x, err = wire.Decode(raw, e.cfg.Codec)
	if err != nil {
		return nil, nil, err
	}
	s, settlement, recent, err := e.transition(parent, candidate, x, history)
	if err != nil {
		return nil, nil, err
	}
	root, err := e.Root(s)
	if err != nil {
		return nil, nil, err
	}
	x.Observation = e.observation(parentRoot, root, settlement, recent)
	raw, err = wire.Encode(x, e.cfg.Codec)
	if err != nil {
		return nil, nil, err
	}
	h := candidate.Copy()
	h.Extra = raw
	s.anchor, err = e.hash(h)
	if err != nil {
		return nil, nil, err
	}
	return h, s, nil
}

// Apply independently verifies historical subset signatures and recomputes
// the carrier's parent-only settlement and resulting root. Finality, canonical
// adoption and epoch scheduling must already have been authenticated by the
// caller. Any failure leaves parent unchanged.
func (e *Engine) Apply(parent *State, h *types.Header, history History) (*State, error) {
	if h == nil {
		return nil, ErrHistory
	}
	x, err := wire.Decode(h.Extra, e.cfg.Codec)
	if err != nil {
		return nil, err
	}
	parentRoot, err := e.Root(parent)
	if err != nil {
		return nil, err
	}
	if !e.acceptsVersion(x.Observation.Version) || x.Observation.PolicyDigest != e.policy || x.Observation.ParentStateRoot != parentRoot {
		return nil, ErrCommitment
	}
	s, settlement, recent, err := e.transition(parent, h, x, history)
	if err != nil {
		return nil, err
	}
	root, err := e.Root(s)
	if err != nil {
		return nil, err
	}
	expected := e.observation(parentRoot, root, settlement, recent)
	x.Observation = expected
	a, err := wire.Encode(x, e.cfg.Codec)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a, h.Extra) {
		return nil, ErrCommitment
	}
	s.anchor, err = e.hash(h)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (e *Engine) acceptsVersion(version uint64) bool {
	if version == 0 {
		version = 1
	}
	return version == e.version()
}
func (e *Engine) observation(parent, result types.Hash, settlement *wire.Settlement, recent *wire.RecentSettlement) wire.Observation {
	out := wire.Observation{PolicyDigest: e.policy, ParentStateRoot: parent, ResultStateRoot: result, Settlement: settlement, Recent: recent}
	if !e.retention.IsZero() {
		out.Version = 2
	}
	return out
}
