package kvstore

import (
	"crypto/rand"
	"os"

	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
)

// NewKeyFile writes a new random node key to path in the go-stablenet
// nodekey format and returns its validator identity.
func NewKeyFile(path string) (Validator, error) {
	for {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return Validator{}, err
		}
		v, err := validatorOf(key)
		if err != nil {
			continue // outside the curve order; draw again
		}
		return v, os.WriteFile(path, privval.FormatKeyFile(key), 0o600)
	}
}

// ReadKeyFile returns the validator identity of a node key file.
func ReadKeyFile(path string) (Validator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Validator{}, err
	}
	key, err := privval.ParseKeyFile(raw)
	if err != nil {
		return Validator{}, err
	}
	return validatorOf(key)
}

func validatorOf(key []byte) (Validator, error) {
	pk, err := ecdsa.PrivateKeyFromBytes(key)
	if err != nil {
		return Validator{}, err
	}
	sk, err := bls.DeriveSecretKey(key)
	if err != nil {
		return Validator{}, err
	}
	return Validator{Address: ecdsa.Address(pk), BLSPublicKey: sk.PublicKey().Bytes()}, nil
}
