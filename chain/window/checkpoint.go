package window

import (
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
)

type checkpointRLP struct {
	Version uint64
	Height  *big.Int
	Hash    types.Hash
	State   rlp.RawValue
}

func (e *Engine) checkAnchor(s *State, trusted *types.Header) error {
	if trusted == nil || trusted.Number.Cmp(e.cfg.Activation) < 0 {
		return ErrHistory
	}
	hash, err := e.hash(trusted)
	if err != nil {
		return err
	}
	if s == nil || s.anchor != hash || s.Height().Cmp(trusted.Number) != 0 || s.data.Parent != trusted.ParentHash {
		return ErrCommitment
	}
	x, err := wire.Decode(trusted.Extra, e.cfg.Codec)
	if err != nil {
		return err
	}
	root, err := e.Root(s)
	if err != nil {
		return err
	}
	if !e.acceptsVersion(x.Observation.Version) || x.Observation.PolicyDigest != e.policy || x.Observation.ResultStateRoot != root {
		return ErrCommitment
	}
	return nil
}

// EncodeCheckpoint requires a caller-trusted carrier and verifies its state
// root. A self-hashed checkpoint cannot establish this carrier's finality.
func (e *Engine) EncodeCheckpoint(s *State, trusted *types.Header) ([]byte, error) {
	if err := e.checkAnchor(s, trusted); err != nil {
		return nil, err
	}
	state, err := e.stateBytes(s)
	if err != nil {
		return nil, err
	}
	b, err := rlp.Encode(checkpointRLP{e.version(), s.Height().Big(), s.anchor, state})
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > e.cfg.CheckpointBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// Recover checks canonical encoding, policy, structural bounds, lineage and
// the root in a caller-trusted carrier. It never trusts the file's own hash.
func (e *Engine) Recover(raw []byte, trusted *types.Header) (*State, error) {
	if uint64(len(raw)) > e.cfg.CheckpointBytes {
		return nil, ErrCapacity
	}
	var c checkpointRLP
	if err := rlp.DecodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if c.Version != e.version() || c.Height == nil || uint64(len(c.State)) > e.cfg.StateBytes {
		return nil, ErrState
	}
	s, err := e.decodeState(c.State)
	if err != nil {
		return nil, err
	}
	if s.data.Height == nil || c.Height.Cmp(s.data.Height) != 0 {
		return nil, ErrState
	}
	s.anchor = c.Hash
	if err := e.checkAnchor(s, trusted); err != nil {
		return nil, err
	}
	return s, nil
}
