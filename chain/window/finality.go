package window

import (
	"errors"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

var ErrFinality = errors.New("window: invalid finality certificate")

func (e *Engine) verifyCertificate(h *types.Header, round uint32, phase types.SealType, seal *types.AggregatedSeal, members []wire.Member) error {
	if seal == nil || len(seal.Signature) != 96 || len(members) == 0 || uint64(len(members)) > uint64(e.cfg.Codec.Validators) {
		return ErrFinality
	}
	var keys [][]byte
	for byteIndex, value := range seal.Sealers {
		for bit := 0; bit < 8; bit++ {
			if value&(1<<bit) == 0 {
				continue
			}
			index := uint64(byteIndex)*8 + uint64(bit)
			if index >= uint64(len(members)) {
				return ErrFinality
			}
			keys = append(keys, members[index].Key)
		}
	}
	if len(keys) < validator.IntegerQuorumSize(len(members)) {
		return ErrFinality
	}
	pk, err := bls.AggregatePublicKeys(keys)
	if err != nil {
		return ErrFinality
	}
	sig, err := bls.DecodeSignature(seal.Signature)
	if err != nil {
		return ErrFinality
	}
	var message []byte
	if h.Number.Cmp(e.cfg.Activation) < 0 {
		if _, err = codec.DecodeExtra(h); err != nil {
			return ErrFinality
		}
		message = codec.SealData(h, round, phase)
	} else {
		message, err = wire.SealData(h, round, phase, e.cfg.Codec)
		if err != nil {
			return ErrFinality
		}
	}
	if !bls.Verify(pk, message, sig) {
		return ErrFinality
	}
	return nil
}

func (e *Engine) verifyAuthority(members []wire.Member) error {
	if _, err := wire.AuthorityDigest(members, e.cfg.Codec); err != nil {
		return ErrHistory
	}
	seen := make(map[types.Address]struct{}, len(members))
	for _, m := range members {
		if _, ok := seen[m.Address]; ok {
			return ErrHistory
		}
		seen[m.Address] = struct{}{}
		if _, err := bls.DecodePublicKey(m.Key); err != nil {
			return ErrHistory
		}
	}
	return nil
}

// VerifyFinality checks both current quorum certificates and the successor's
// certificates for its parent, using the authority governing each target.
// Observation subsets never satisfy this quorum check by themselves. The
// caller still verifies header fields, execution, epoch transitions, registered
// key ownership and canonical adoption; this is not a full block verifier.
func (e *Engine) VerifyFinality(h *types.Header, history History) error {
	if h == nil || history == nil || h.Number.Cmp(e.cfg.Activation) < 0 {
		return ErrHistory
	}
	x, err := wire.Decode(h.Extra, e.cfg.Codec)
	if err != nil {
		return err
	}
	members, err := history.Authority(h)
	if err != nil {
		return err
	}
	if err = e.verifyAuthority(members); err != nil {
		return err
	}
	if err = e.verifyCertificate(h, x.Legacy.Round, types.PrepareSeal, x.Legacy.PreparedSeal, members); err != nil {
		return err
	}
	if err = e.verifyCertificate(h, x.Legacy.Round, types.CommitSeal, x.Legacy.CommittedSeal, members); err != nil {
		return err
	}
	parentNumber, _ := h.Number.Sub(types.HeightFromUint64(1))
	parent, err := history.Header(h.ParentHash, parentNumber)
	if err != nil {
		return err
	}
	parentHash, err := e.hash(parent)
	if err != nil || parent.Number.Cmp(parentNumber) != 0 || parentHash != h.ParentHash {
		return ErrHistory
	}
	if parentNumber.IsZero() {
		return nil
	}
	previous, err := history.Authority(parent)
	if err != nil {
		return err
	}
	if err = e.verifyAuthority(previous); err != nil {
		return err
	}
	if err = e.verifyCertificate(parent, x.Legacy.PrevRound, types.PrepareSeal, x.Legacy.PrevPreparedSeal, previous); err != nil {
		return err
	}
	return e.verifyCertificate(parent, x.Legacy.PrevRound, types.CommitSeal, x.Legacy.PrevCommittedSeal, previous)
}

// VerifyAndApply checks finality and the observation transition before
// returning a new state. A failed certificate cannot partially advance parent.
// It does not replace the application's full block and epoch verification.
func (e *Engine) VerifyAndApply(parent *State, h *types.Header, history History) (*State, error) {
	if err := e.VerifyFinality(h, history); err != nil {
		return nil, err
	}
	return e.Apply(parent, h, history)
}
