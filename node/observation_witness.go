package node

import (
	"bytes"
	"math/big"
	"path/filepath"
	"sort"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

type observationWitness struct {
	Height *big.Int
	Hash   types.Hash
	Round  uint32
	Phase  uint8
	Source types.Address
	Seal   []byte
}

func witnessLess(a, b observationWitness) bool {
	if cmp := a.Height.Cmp(b.Height); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.Hash[:], b.Hash[:]); cmp != 0 {
		return cmp < 0
	}
	if a.Round != b.Round {
		return a.Round < b.Round
	}
	if a.Phase != b.Phase {
		return a.Phase < b.Phase
	}
	return bytes.Compare(a.Source[:], b.Source[:]) < 0
}
func sameWitness(a, b observationWitness) bool {
	return a.Height.Cmp(b.Height) == 0 && a.Hash == b.Hash && a.Round == b.Round && a.Phase == b.Phase && a.Source == b.Source
}
func (r *observationRuntime) liveWitness(w observationWitness, head *types.Header) bool {
	if w.Height == nil || w.Height.Sign() < 0 || w.Height.Cmp(r.cfg.Policy.Activation.Big()) < 0 {
		return false
	}
	age, ok := head.Number.AddUint64(1).Sub(types.MustHeightFromBig(w.Height))
	return ok && !age.IsZero() && age.CmpUint64(r.cfg.Policy.Window) <= 0
}
func (r *observationRuntime) verifyWitness(w observationWitness, history *window.BranchHistory) error {
	if w.Height == nil || w.Height.Sign() < 0 || (w.Phase != uint8(types.PrepareSeal) && w.Phase != uint8(types.CommitSeal)) || len(w.Seal) != 96 {
		return window.ErrProof
	}
	target, err := history.Header(w.Hash, types.MustHeightFromBig(w.Height))
	if err != nil {
		return err
	}
	members, err := history.Authority(target)
	if err != nil {
		return err
	}
	for _, member := range members {
		if member.Address != w.Source {
			continue
		}
		key, err := bls.DecodePublicKey(member.Key)
		if err != nil {
			return err
		}
		signature, err := bls.DecodeSignature(w.Seal)
		if err != nil {
			return err
		}
		message, err := wire.SealData(target, w.Round, types.SealType(w.Phase), r.cfg.Policy.Codec)
		if err != nil || !bls.Verify(key, message, signature) {
			return window.ErrProof
		}
		return nil
	}
	return window.ErrProof
}
func (r *observationRuntime) loadWitnesses() error {
	raw, err := observationRead(r.fs, filepath.Join(r.dir, "witness.rlp"), r.cfg.WitnessBytes)
	if fsys.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	items, err := rlp.ListItems(raw)
	if err != nil || uint64(len(items)) > uint64(r.cfg.WitnessItems) {
		return window.ErrCapacity
	}
	var witnesses []observationWitness
	if err := rlp.DecodeStrict(raw, &witnesses); err != nil {
		return err
	}
	history, err := r.history(r.chain)
	if err != nil {
		return err
	}
	for i, w := range witnesses {
		if w.Height == nil || w.Height.Sign() < 0 || (i > 0 && !witnessLess(witnesses[i-1], w)) {
			return window.ErrState
		}
		if !r.liveWitness(w, r.chain.Head()) {
			continue
		}
		if err := r.verifyWitness(w, history); err != nil {
			return err
		}
		r.witnesses = append(r.witnesses, w)
	}
	return nil
}

// observeSeals sees only detached entries retained after ordinary signature
// verification. Historical membership and BLS are checked independently before
// durable intake. No diagnostic ledger or unverified packet supplies authority.
func (r *observationRuntime) observeSeals(prepared, committed []consensus.ExtraSealEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unavailable != nil {
		return
	}
	head := r.chain.Head()
	if head == nil {
		return
	}
	history, err := r.history(r.chain)
	if err != nil {
		r.witnessError = err.Error()
		return
	}
	previous := r.witnesses
	var next []observationWitness
	for _, w := range previous {
		if r.liveWitness(w, head) {
			next = append(next, w)
		}
	}
	total := len(prepared) + len(committed)
	checks := uint64(r.cfg.WitnessChecksPerStep)
	if checks > uint64(total) {
		checks = uint64(total)
	}
	for offset := uint64(0); offset < checks; offset++ {
		index := (r.witnessCursor + offset) % uint64(total)
		phase := types.PrepareSeal
		var entry consensus.ExtraSealEntry
		if index < uint64(len(prepared)) {
			entry = prepared[index]
		} else {
			entry = committed[index-uint64(len(prepared))]
			phase = types.CommitSeal
		}
		target := r.chain.HeaderByHash(entry.Digest)
		if target == nil || target.Number.Cmp(entry.View.Sequence) != 0 {
			continue
		}
		// Retain the verified message's existing uint32 BLS signing domain.
		// A stored local certificate does not choose a later successor's round.
		round := entry.View.Round.RefLow32() //wbft:low64 HH-74
		w := observationWitness{target.Number.Big(), entry.Digest, round, uint8(phase), entry.Source, bytes.Clone(entry.Seal)}
		if !r.liveWitness(w, head) {
			continue
		}
		duplicate := false
		for _, old := range next {
			if sameWitness(old, w) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if uint64(len(next)) >= uint64(r.cfg.WitnessItems) {
			r.witnessDropped++
			continue
		}
		if err := r.verifyWitness(w, history); err != nil {
			continue
		}
		candidate := append(append([]observationWitness(nil), next...), w)
		encoded, err := rlp.Encode(candidate)
		if err != nil || uint64(len(encoded)) > r.cfg.WitnessBytes {
			r.witnessDropped++
			continue
		}
		next = candidate
	}
	if total > 0 {
		r.witnessCursor = (r.witnessCursor + checks) % uint64(total)
	}
	sort.SliceStable(next, func(i, j int) bool { return witnessLess(next[i], next[j]) })
	encoded, err := rlp.Encode(next)
	if err != nil {
		r.witnessError = err.Error()
		return
	}
	old, _ := rlp.Encode(previous)
	if bytes.Equal(old, encoded) {
		return
	}
	if err := observationWrite(r.fs, filepath.Join(r.dir, "witness.rlp"), encoded); err != nil {
		r.witnessError = err.Error()
		return
	}
	r.witnesses = next
	r.witnessError = ""
}

// selectProofs adds only disjoint individual indices to an intact certificate.
// Older targets are considered before newer ones within the explicit k window.
func (r *observationRuntime) selectProofs(h *types.Header, legacy *types.WBFTExtra, history *window.BranchHistory) ([]wire.Proof, error) {
	type targetRound struct {
		header *types.Header
		round  uint32
	}
	var targets []targetRound
	parent := r.chain.HeaderByHash(h.ParentHash)
	round := legacy.PrevRound
	for age := uint64(1); age <= r.cfg.Policy.Window && parent != nil && parent.Number.Cmp(r.cfg.Policy.Activation) >= 0; age++ {
		if uint64(len(targets)) >= r.cfg.HistoryWalk {
			return nil, window.ErrLookupLimit
		}
		targets = append(targets, targetRound{parent, round})
		x, err := codec.DecodeConsensusExtra(parent)
		if err != nil {
			return nil, err
		}
		round = x.PrevRound
		parent = r.chain.HeaderByHash(parent.ParentHash)
	}
	var proofs []wire.Proof
	for i := len(targets) - 1; i >= 0; i-- {
		target := targets[i]
		hash := codec.BlockHash(target.header)
		members, err := history.Authority(target.header)
		if err != nil {
			return nil, err
		}
		authority, err := wire.AuthorityDigest(members, r.cfg.Policy.Codec)
		if err != nil {
			return nil, err
		}
		for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
			if uint64(len(proofs)) >= uint64(r.cfg.Policy.Codec.Proofs) {
				return proofs, nil
			}
			var bitmap types.SealerSet
			var signatures [][]byte
			if i == 0 {
				certificate := legacy.PrevPreparedSeal
				if phase == types.CommitSeal {
					certificate = legacy.PrevCommittedSeal
				}
				if certificate != nil {
					bitmap = bytes.Clone(certificate.Sealers)
					signatures = append(signatures, certificate.Signature)
				}
			}
			for index, member := range members {
				present := false
				for _, set := range bitmap.Sealers() {
					if uint64(set) == uint64(index) {
						present = true
						break
					}
				}
				if present {
					continue
				}
				for _, w := range r.witnesses {
					if w.Hash == hash && w.Height.Cmp(target.header.Number.Big()) == 0 && w.Round == target.round && w.Phase == uint8(phase) && w.Source == member.Address {
						bitmap.SetSealer(uint32(index))
						signatures = append(signatures, w.Seal)
						break
					}
				}
			}
			if len(signatures) == 0 {
				continue
			}
			signature, err := bls.AggregateSignatures(signatures)
			if err != nil {
				return nil, err
			}
			proofs = append(proofs, wire.Proof{Height: target.header.Number, Hash: hash, Round: target.round, Authority: authority, Phase: phase, Bitmap: bitmap, Signature: signature.Bytes()})
		}
	}
	return proofs, nil
}
