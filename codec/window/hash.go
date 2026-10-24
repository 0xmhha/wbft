package window

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// FilteredHeader preserves all proof and observation fields. Only the nested
// legacy current round and current seals change. The input is never mutated.
func FilteredHeader(h *types.Header, round uint32, l Limits) (*types.Header, error) {
	if h == nil {
		return nil, ErrFormat
	}
	x, err := Decode(h.Extra, l)
	if err != nil {
		return nil, err
	}
	x.Legacy.Round = round
	x.Legacy.PreparedSeal = nil
	x.Legacy.CommittedSeal = nil
	raw, err := Encode(x, l)
	if err != nil {
		return nil, err
	}
	out := h.Copy()
	out.Extra = raw
	return out, nil
}

// HashWithRound returns the explicitly filtered hash. Unsupported envelopes
// return an error rather than an absent-header hash.
func HashWithRound(h *types.Header, round uint32, l Limits) (types.Hash, error) {
	fh, err := FilteredHeader(h, round, l)
	if err != nil {
		return types.Hash{}, err
	}
	b, err := codec.EncodeHeader(fh)
	if err != nil {
		return types.Hash{}, err
	}
	return keccak.Sum256(b), nil
}

// BlockHash returns the round-zero filtered hash for a WBFT-difficulty header.
// Other difficulties retain their ordinary header hash after envelope checking.
func BlockHash(h *types.Header, l Limits) (types.Hash, error) {
	if h == nil {
		return types.Hash{}, ErrFormat
	}
	if h.Difficulty != nil && h.Difficulty.IsUint64() && h.Difficulty.Uint64() == types.WBFTDifficulty {
		return HashWithRound(h, 0, l)
	}
	if _, err := Decode(h.Extra, l); err != nil {
		return types.Hash{}, err
	}
	b, err := codec.EncodeHeader(h)
	if err != nil {
		return types.Hash{}, err
	}
	return keccak.Sum256(b), nil
}

// SealData retains the existing round/phase signing domain for an explicit
// envelope; it does not authenticate a historical certificate or its timing.
func SealData(h *types.Header, round uint32, phase types.SealType, l Limits) ([]byte, error) {
	if phase != types.PrepareSeal && phase != types.CommitSeal {
		return nil, ErrFormat
	}
	hash, err := HashWithRound(h, round, l)
	if err != nil {
		return nil, err
	}
	return keccak.Sum256Bytes(hash[:], []byte{byte(phase)}), nil
}

// AuthorityDigest commits the historical signer-index order. Callers must
// obtain that authority from authenticated history, including key ownership.
func AuthorityDigest(members []Member, l Limits) (types.Hash, error) {
	if !l.valid() || len(members) == 0 || uint64(len(members)) > uint64(l.Validators) {
		return types.Hash{}, ErrLimit
	}
	type entry struct {
		Index   uint64
		Address types.Address
		Key     []byte
	}
	var entries []entry
	for i, m := range members {
		if len(m.Key) != 48 {
			return types.Hash{}, ErrFormat
		}
		entries = append(entries, entry{uint64(i), m.Address, m.Key})
	}
	b, err := rlp.Encode([]any{[]byte("WBFT-PARTICIPATION-AUTHORITY/1"), uint64(1), entries})
	if err != nil {
		return types.Hash{}, err
	}
	return keccak.Sum256(b), nil
}
