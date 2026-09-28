package ecdsa

import (
	stdecdsa "crypto/ecdsa"
	"errors"

	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// PrivateKey is a secp256k1 private key (a node key).
type PrivateKey = stdecdsa.PrivateKey

// PublicKey is a secp256k1 public key.
type PublicKey = stdecdsa.PublicKey

// SignatureLength is the length of R || S || V.
//
// Spec: WBFT-TYPE-003
const SignatureLength = 65

// Errors of signer checks. Recovery failures are returned as the error of
// the recovery (length, recovery id, or failed recovery).
var (
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrUnauthorizedAddress = errors.New("unauthorized address")
)

// PrivateKeyFromBytes returns the key with the 32-byte big-endian scalar b.
// It fails unless 0 < b < n.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	return crypto.ToECDSA(b)
}

// PrivateKeyBytes returns the 32-byte big-endian scalar of k.
func PrivateKeyBytes(k *PrivateKey) []byte {
	return crypto.FromECDSA(k)
}

// PubkeyToAddress returns keccak256(X || Y)[12:32] of the uncompressed key.
//
// Spec: WBFT-CRYPTO-010
func PubkeyToAddress(pub *PublicKey) types.Address {
	return crypto.PubkeyToAddress(*pub)
}

// Address returns the address of the node key k.
func Address(k *PrivateKey) types.Address {
	return crypto.PubkeyToAddress(k.PublicKey)
}

// Sign signs hash with k and returns R || S || V with V in {0, 1}. The
// signature is deterministic (RFC 6979) and has a low S.
//
// Spec: WBFT-CRYPTO-011, WBFT-CRYPTO-017
func Sign(hash types.Hash, k *PrivateKey) ([]byte, error) {
	return crypto.Sign(hash[:], k)
}

// SignData is ecdsa_sign(k, data): the signature over keccak256(data).
//
// Spec: WBFT-CRYPTO-011
func SignData(data []byte, k *PrivateKey) ([]byte, error) {
	return Sign(crypto.Keccak256Hash(data), k)
}

// RecoverAddress recovers the signer of hash from sig with the acceptance
// rules of the cgo build of the reference: sig must be 65 bytes with a
// recovery byte below 4, R and S must lie in [1, n-1], and public-key
// recovery must succeed. A high S is accepted.
//
// Spec: WBFT-CRYPTO-013, WBFT-CRYPTO-014
func RecoverAddress(hash types.Hash, sig []byte) (types.Address, error) {
	pub, err := crypto.SigToPub(hash[:], sig)
	if err != nil {
		return types.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// RecoverDataSigner is ecdsa_recover_address(data, sig): RecoverAddress over
// keccak256(data).
//
// Spec: WBFT-CRYPTO-013
func RecoverDataSigner(data, sig []byte) (types.Address, error) {
	return RecoverAddress(crypto.Keccak256Hash(data), sig)
}

// CheckValidatorSignature is check_validator_signature: it recovers the
// signer of data and returns it if isMember reports it as a validator. A
// recovery failure is returned as is; a non-member fails with
// ErrUnauthorizedAddress.
//
// Spec: WBFT-CRYPTO-015
func CheckValidatorSignature(isMember func(types.Address) bool, data, sig []byte) (types.Address, error) {
	signer, err := RecoverDataSigner(data, sig)
	if err != nil {
		return types.Address{}, err
	}
	if isMember(signer) {
		return signer, nil
	}
	return types.Address{}, ErrUnauthorizedAddress
}

// CheckSigner reports whether sig over data was made by want: a recovery
// failure is returned as is, another signer fails with ErrInvalidSignature.
//
// Spec: WBFT-CRYPTO-016
func CheckSigner(data, sig []byte, want types.Address) error {
	signer, err := RecoverDataSigner(data, sig)
	if err != nil {
		return err
	}
	if signer != want {
		return ErrInvalidSignature
	}
	return nil
}
