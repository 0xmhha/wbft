package types

import (
	"github.com/ethereum/go-ethereum/common"
)

// Address is a 20-byte account address.
//
// Spec: WBFT-TYPE-001
type Address = common.Address

// Hash is a 32-byte hash.
//
// Spec: WBFT-TYPE-002
type Hash = common.Hash

// Nonce is the 8-byte header nonce.
type Nonce [8]byte

// Bloom is the 256-byte header log bloom.
type Bloom [256]byte

// Protocol constants of A-01 section 4.
const (
	// SealLength is the length of one BLS seal (a compressed G2 point).
	//
	// Spec: WBFT-PARAM-011
	SealLength = 96

	// ExtraVanity is the vanity length a proposer pads its builder extra to.
	//
	// Spec: WBFT-PARAM-012
	ExtraVanity = 32

	// MaxIstanbulMsgSize is the largest istanbul/100 frame a node reads. The
	// transport adapter enforces it.
	MaxIstanbulMsgSize = 10485760

	// DiligenceDenominator is the unit of diligence (10^-6).
	DiligenceDenominator uint64 = 1_000_000

	// DefaultDiligence is the diligence of a new candidate and of the genesis
	// candidates: 95 % of the maximum 2 * DiligenceDenominator.
	DefaultDiligence uint64 = 2 * DiligenceDenominator * 95 / 100

	// InitialGasTip is the genesis gas tip (wei) when the chain configuration
	// does not set one.
	InitialGasTip uint64 = 27_600_000_000_000

	// MaxGasLimit is the upper bound of Header.GasLimit (2^63 - 1).
	MaxGasLimit uint64 = 0x7fffffffffffffff
)

// WBFTDifficulty is the difficulty of every WBFT block with Number >= 1. It
// also selects the WBFT block-hash rule.
//
// Spec: WBFT-PARAM-010
const WBFTDifficulty = 1

// EmptyUncleHash is keccak256(rlp([])), the required UncleHash.
var EmptyUncleHash = common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")

// SealType selects the seal a validator signs: PrepareSeal in PREPARE
// messages, CommitSeal in COMMIT messages.
//
// Spec: WBFT-TYPE-005
type SealType uint8

// Seal types.
const (
	PrepareSeal SealType = 0
	CommitSeal  SealType = 1
)

// Eligibility is the proposer-eligibility answer of an authority snapshot.
type Eligibility uint8

// Eligibility values.
const (
	Eligible   Eligibility = iota
	Ineligible             // blacklisted in the parent state
	Unknown                // parent state not available, or address outside the scope
)

// CandidateEntry is one epoch candidate with its BLS public key. An
// unregistered key is an empty slice.
type CandidateEntry struct {
	Addr         Address
	BLSPublicKey []byte
}
