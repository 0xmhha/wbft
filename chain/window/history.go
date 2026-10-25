package window

import (
	"errors"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

// ErrLookupLimit means authenticated history needs a nearer checkpoint or a
// larger local lookup budget. It does not establish an invalid block or proof.
var ErrLookupLimit = errors.New("window: historical lookup budget exhausted")

// BranchHistory adapts the application's hash-addressed header store. It
// follows the candidate's parent branch, never a canonical low-width index.
// The application must already have authenticated stored epoch information,
// key ownership and canonical adoption. This adapter does not establish trust
// in a supplied chain database or make a proposed epoch transition valid.
type BranchHistory struct {
	engine   *Engine
	chain    types.ChainReader
	schedule *types.Config
	maxWalk  uint64
}

// NewBranchHistory snapshots the epoch schedule and binds its chain identity
// to the observation policy. maxWalk bounds one Authority lookup, excluding
// the constructor's single genesis read. It has no default. Mutating caller
// configuration after construction cannot change the captured schedule.
func NewBranchHistory(engine *Engine, chain types.ChainReader, cfg *types.Config, maxWalk uint64) (*BranchHistory, error) {
	if engine == nil || chain == nil || cfg == nil || cfg.ChainID == nil || cfg.ChainID.Cmp(engine.cfg.ChainID) != 0 || cfg.Base().EpochLength == 0 || maxWalk == 0 {
		return nil, ErrPolicy
	}
	var transitions []types.Transition
	for _, t := range cfg.EpochTransitions() {
		if t.Block == nil || t.Block.Sign() < 0 || t.Length == 0 {
			return nil, ErrPolicy
		}
		transitions = append(transitions, types.Transition{Block: t.Block, WBFT: &types.WBFTParams{EpochLength: t.Length}})
	}
	schedule := types.NewConfig(types.WBFTParams{EpochLength: cfg.Base().EpochLength}, transitions, types.GenesisInit{}, cfg.ChainID)
	h := &BranchHistory{engine, chain, schedule, maxWalk}
	genesis, err := h.Header(engine.cfg.GenesisHash, types.Height{})
	if err != nil {
		return nil, err
	}
	x, err := codec.DecodeExtra(genesis)
	if err != nil {
		return nil, err
	}
	if _, err = h.members(x.EpochInfo); err != nil {
		return nil, err
	}
	return h, nil
}

// Header returns an owned header after checking its full height and hash.
// Genesis must match the policy's genesis hash. Reads never call Header or
// HeaderByNumber, whose index arguments may truncate a historical height.
func (b *BranchHistory) Header(hash types.Hash, height types.Height) (*types.Header, error) {
	h := b.chain.HeaderByHash(hash)
	if h == nil {
		return nil, ErrHistory
	}
	h = h.Copy()
	if h.Number.Cmp(height) != 0 {
		return nil, ErrHistory
	}
	if height.IsZero() && hash != b.engine.cfg.GenesisHash {
		return nil, ErrHistory
	}
	if uint64(len(h.Extra)) > b.engine.cfg.Codec.ExtraBytes {
		return nil, ErrCapacity
	}
	if _, err := codec.EncodeHeader(h); err != nil {
		return nil, ErrHistory
	}
	if h.Number.Cmp(b.engine.cfg.Activation) >= 0 {
		x, err := wire.Decode(h.Extra, b.engine.cfg.Codec)
		if err != nil || !b.engine.acceptsVersion(x.Observation.Version) || x.Observation.PolicyDigest != b.engine.policy {
			return nil, ErrHistory
		}
	}
	actual, err := b.engine.hash(h)
	if err != nil || actual != hash {
		return nil, ErrHistory
	}
	return h, nil
}

func (b *BranchHistory) members(info *types.EpochInfo) ([]wire.Member, error) {
	if info == nil || len(info.Validators) == 0 || len(info.BLSPublicKeys) != len(info.Validators) {
		return nil, ErrHistory
	}
	if uint64(len(info.Validators)) > uint64(b.engine.cfg.Codec.Validators) {
		return nil, ErrCapacity
	}
	out := make([]wire.Member, 0, len(info.Validators))
	seen := make(map[types.Address]struct{}, len(info.Validators))
	for i, index := range info.Validators {
		if uint64(index) >= uint64(len(info.Candidates)) {
			return nil, ErrHistory
		}
		a := info.Candidates[index].Addr
		if _, ok := seen[a]; ok {
			return nil, ErrHistory
		}
		seen[a] = struct{}{}
		if _, err := bls.DecodePublicKey(info.BLSPublicKeys[i]); err != nil {
			return nil, ErrHistory
		}
		out = append(out, wire.Member{Address: a, Key: append([]byte(nil), info.BLSPublicKeys[i]...)})
	}
	return out, nil
}

func (b *BranchHistory) epochMembers(h *types.Header) ([]wire.Member, error) {
	var x *types.WBFTExtra
	var err error
	if h.Number.Cmp(b.engine.cfg.Activation) < 0 {
		x, err = codec.DecodeExtra(h)
	} else {
		var envelope *wire.Extra
		envelope, err = wire.Decode(h.Extra, b.engine.cfg.Codec)
		if err == nil {
			x = envelope.Legacy
		}
	}
	if err != nil {
		return nil, ErrHistory
	}
	return b.members(x.EpochInfo)
}

// Authority resolves the governing epoch on target's actual parent branch.
// target may be an unstored candidate; epoch headers must come from the
// authenticated store. Neither a same-height canonical alternative nor a
// local certificate's current round selects the historical authority.
func (b *BranchHistory) Authority(target *types.Header) ([]wire.Member, error) {
	if target == nil {
		return nil, ErrHistory
	}
	if target.Number.IsZero() {
		hash, err := b.engine.hash(target)
		if err != nil || hash != b.engine.cfg.GenesisHash {
			return nil, ErrHistory
		}
		g, err := b.Header(hash, types.Height{})
		if err != nil {
			return nil, err
		}
		return b.epochMembers(g)
	}
	parent, _ := target.Number.Sub(types.HeightFromUint64(1))
	boundary, err := validator.LastEpochBlock(b.schedule, parent)
	if err != nil {
		return nil, err
	}
	distance, ok := parent.Sub(boundary)
	if !ok {
		return nil, ErrHistory
	}
	if distance.AddUint64(1).CmpUint64(b.maxWalk) > 0 {
		return nil, ErrLookupLimit
	}
	hash := target.ParentHash
	number := parent
	for {
		header, err := b.Header(hash, number)
		if err != nil {
			return nil, err
		}
		if number.Cmp(boundary) == 0 {
			return b.epochMembers(header)
		}
		if number.IsZero() {
			return nil, ErrHistory
		}
		hash = header.ParentHash
		number, _ = number.Sub(types.HeightFromUint64(1))
	}
}
