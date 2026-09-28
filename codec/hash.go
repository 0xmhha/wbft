package codec

import (
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// absentHeaderHash is keccak256(0xc0): the hash of the RLP of an absent
// header, which the reference returns as hash_with_round of a header whose
// extra does not decode.
var absentHeaderHash = keccak.Sum256(rlp.EmptyList)

// FilteredHeader returns a copy of h whose Extra is the re-encoding of its
// decoded WBFTExtra without PreparedSeal and CommittedSeal and with Round
// replaced by round. Every other field is kept. It fails when the extra does
// not decode.
//
// Spec: WBFT-ENC-080, WBFT-ENC-090
func FilteredHeader(h *types.Header, round uint32) (*types.Header, error) {
	x, err := DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	x.PreparedSeal = nil
	x.CommittedSeal = nil
	x.Round = round
	c := h.Copy()
	if err := SetExtra(c, x); err != nil {
		return nil, err
	}
	return c, nil
}

// HashWithRound is keccak256(rlp(FilteredHeader(h, round))), or
// keccak256(0xc0) when the extra does not decode. It does not depend on
// Difficulty.
//
// Spec: WBFT-ENC-081
func HashWithRound(h *types.Header, round uint32) types.Hash {
	fh, err := FilteredHeader(h, round)
	if err != nil {
		return absentHeaderHash
	}
	b, err := EncodeHeader(fh)
	if err != nil {
		return absentHeaderHash
	}
	return keccak.Sum256(b)
}

// HeaderHash is keccak256(rlp(h)), the Ethereum header hash.
func HeaderHash(h *types.Header) types.Hash {
	b, err := EncodeHeader(h)
	if err != nil {
		// Only a negative Difficulty or BaseFee cannot be encoded, and a
		// decoded header never has one; such a header hashes to zero.
		return types.Hash{}
	}
	return keccak.Sum256(b)
}

var bigOne = big.NewInt(types.WBFTDifficulty)

// BlockHash is block_hash(h): keccak256(rlp(FilteredHeader(h, 0))) when
// Difficulty is 1 and the extra decodes, and keccak256(rlp(h)) otherwise. It
// does not depend on PreparedSeal, CommittedSeal or Round.
//
// Spec: WBFT-ENC-082, WBFT-ENC-084
func BlockHash(h *types.Header) types.Hash {
	if h.Difficulty != nil && h.Difficulty.Cmp(bigOne) == 0 {
		if fh, err := FilteredHeader(h, 0); err == nil {
			return HeaderHash(fh)
		}
	}
	return HeaderHash(h)
}

// SealData is seal_data(h, round, t) = keccak256(hash_with_round(h, round) ||
// t), the 32-byte message a validator signs with its BLS key.
//
// A seal is the BLS signature of the sealer over this value.
//
// Spec: WBFT-CRYPTO-040, WBFT-CRYPTO-041, WBFT-CRYPTO-042, WBFT-CRYPTO-044
func SealData(h *types.Header, round uint32, t types.SealType) []byte {
	hr := HashWithRound(h, round)
	return keccak.Sum256Bytes(hr[:], []byte{byte(t)})
}

// RandaoData is randao_data(chainID, number) = keccak256(be_min(chainID) ||
// 0x01 || be_min(number)) over the full number.
//
// Spec: WBFT-CRYPTO-050
func RandaoData(chainID *big.Int, number types.Height) []byte {
	var cid []byte
	if chainID != nil {
		cid = chainID.Bytes()
	}
	return keccak.Sum256Bytes(cid, []byte{0x01}, number.Bytes())
}

// DedupKey is keccak256(rlp_string(payload)): the key under which a node
// records a consensus message payload as seen.
//
// Spec: WBFT-MSG-060
func DedupKey(payload []byte) types.Hash {
	return keccak.Sum256(rlp.EncodeString(payload))
}
