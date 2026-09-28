package keccak

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Sum256 returns the legacy Keccak-256 hash (Keccak padding, not SHA3-256)
// of the concatenation of data.
//
// Spec: WBFT-CRYPTO-001
func Sum256(data ...[]byte) common.Hash {
	return crypto.Keccak256Hash(data...)
}

// Sum256Bytes is Sum256 returned as a byte slice.
func Sum256Bytes(data ...[]byte) []byte {
	return crypto.Keccak256(data...)
}
