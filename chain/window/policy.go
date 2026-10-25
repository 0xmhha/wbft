// Package window verifies and settles participation observations without
// changing candidate diligence, validator selection, fees or consensus rules.
// A caller must explicitly supply authenticated history and an observation
// policy. Using this package does not activate a network fork.
package window

import (
	"errors"
	"math"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

var (
	ErrPolicy     = errors.New("window: invalid observation policy")
	ErrState      = errors.New("window: invalid observation state")
	ErrHistory    = errors.New("window: authenticated history unavailable")
	ErrProof      = errors.New("window: invalid historical observation")
	ErrCommitment = errors.New("window: observation commitment mismatch")
	ErrCapacity   = errors.New("window: observation capacity exceeded")
)

// Config has no defaults. Limits bind observation work and encoded state, not
// the lifetime disk size of a chain. AddressRows bounds each sorted count set.
// Capacity exhaustion is an observation error; this package does not turn it
// into a legacy block rejection or decide network operating parameters.
type Config struct {
	ChainID         *big.Int
	GenesisHash     types.Hash
	Activation      types.Height
	Window          uint64
	Codec           wire.Limits
	StateBytes      uint64
	CheckpointBytes uint64
	AddressRows     uint32
}

// History supplies already authenticated chain history. Header must resolve
// the full height and hash, not a truncated index. Authority must return the
// unique historical signer-index order governing target, including trusted
// key ownership. This interface does not create a snapshot trust anchor.
type History interface {
	Header(hash types.Hash, height types.Height) (*types.Header, error)
	Authority(target *types.Header) ([]wire.Member, error)
}

// Engine is an immutable observation policy. Each transition returns a new
// state; no local wall clock, network source or economic module is consulted.
type Engine struct {
	cfg       Config
	policy    types.Hash
	retention types.Height
}

// New binds every structural, state and checkpoint limit into policy identity.
func New(c Config) (*Engine, error) {
	if c.ChainID == nil || c.ChainID.Sign() < 0 || c.GenesisHash == (types.Hash{}) || c.Activation.IsZero() || c.Window == 0 || c.Codec.ExtraBytes == 0 || c.Codec.Proofs == 0 || c.Codec.SettlementRows == 0 || c.Codec.Validators == 0 || c.StateBytes == 0 || c.CheckpointBytes == 0 || c.CheckpointBytes >= math.MaxInt64 || c.AddressRows == 0 {
		return nil, ErrPolicy
	}
	c.ChainID = new(big.Int).Set(c.ChainID)
	b, err := rlp.Encode([]any{[]byte("WBFT-PARTICIPATION-POLICY/1"), uint64(1), c.ChainID, c.GenesisHash, c.Activation.Big(), c.Window, c.Codec, c.StateBytes, c.CheckpointBytes, c.AddressRows})
	if err != nil {
		return nil, err
	}
	return &Engine{cfg: c, policy: keccak.Sum256(b)}, nil
}

func (e *Engine) Digest() types.Hash      { return e.policy }
func (e *Engine) CheckpointLimit() uint64 { return e.cfg.CheckpointBytes }

func (e *Engine) hash(h *types.Header) (types.Hash, error) {
	if h == nil {
		return types.Hash{}, ErrHistory
	}
	if h.Number.Cmp(e.cfg.Activation) < 0 {
		if _, err := codec.DecodeExtra(h); err != nil {
			return types.Hash{}, err
		}
		return codec.BlockHash(h), nil
	}
	return wire.BlockHash(h, e.cfg.Codec)
}

// Initial starts immediately before Activation from a caller-trusted parent.
// Trusting this parent is an explicit bootstrap requirement, not a conclusion
// drawn from a self-hashed file. Earlier targets receive no opportunities.
func (e *Engine) Initial(parent *types.Header) (*State, error) {
	before, _ := e.cfg.Activation.Sub(types.HeightFromUint64(1))
	if parent == nil || parent.Number.Cmp(before) != 0 {
		return nil, ErrHistory
	}
	hash, err := e.hash(parent)
	if err != nil {
		return nil, err
	}
	s := &State{data: stateRLP{Version: e.version(), Policy: e.policy, Height: before.Big(), Parent: parent.ParentHash, Settled: before.Big(), Matured: before.Big()}, anchor: hash}
	if !e.retention.IsZero() {
		s.recent = &recentState{From: e.cfg.Activation.Big()}
	}
	if _, err = e.stateBytes(s); err != nil {
		return nil, err
	}
	return s, nil
}
