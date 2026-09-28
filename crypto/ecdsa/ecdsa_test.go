package ecdsa

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// secp256k1 group order n.
var secpN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func key0(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("wbft-spec-vector-key-0")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func withRSV(sig []byte, r, s *big.Int, v byte) []byte {
	out := append([]byte(nil), sig...)
	if r != nil {
		r.FillBytes(out[0:32])
	}
	if s != nil {
		s.FillBytes(out[32:64])
	}
	out[64] = v
	return out
}

// A-02 §8.2.
func TestSignAndRecover(t *testing.T) {
	k := key0(t)
	if a := Address(k); hex.EncodeToString(a[:]) != "376ab524a47492d1c8222c67c0cff8d5fec34112" {
		t.Fatalf("address %x", a)
	}
	sig, err := SignData([]byte("wbft"), k)
	if err != nil {
		t.Fatal(err)
	}
	want := "20a777b74c9e9838257309f91fd348d53485fb0bedbdcabf4a41faeb17b8ce3565182fbdf4d2e6a7f69491e35053b331f003523e36f6acddf45b22bbedb3757c00"
	if hex.EncodeToString(sig) != want {
		t.Fatalf("signature %x", sig)
	}
	// low S
	if new(big.Int).SetBytes(sig[32:64]).Cmp(new(big.Int).Rsh(secpN, 1)) > 0 {
		t.Error("high S produced")
	}
	signer, err := RecoverDataSigner([]byte("wbft"), sig)
	if err != nil || signer != Address(k) {
		t.Fatalf("recover: %x %v", signer, err)
	}
	// The high-S twin (R, n-S, V^1) recovers the same signer.
	s := new(big.Int).SetBytes(sig[32:64])
	twin := withRSV(sig, nil, new(big.Int).Sub(secpN, s), sig[64]^1)
	if got, err := RecoverDataSigner([]byte("wbft"), twin); err != nil || got != Address(k) {
		t.Errorf("high-S twin: %x %v", got, err)
	}
	if err := CheckSigner([]byte("wbft"), twin, Address(k)); err != nil {
		t.Errorf("CheckSigner of the twin: %v", err)
	}
}

func TestRecoveryRules(t *testing.T) {
	k := key0(t)
	data := []byte("wbft")
	sig, _ := SignData(data, k)
	v := sig[64]
	nm1 := new(big.Int).Sub(secpN, big.NewInt(1))
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	fails := map[string][]byte{
		"len0":   nil,
		"len64":  sig[:64],
		"len66":  append(append([]byte(nil), sig...), 0),
		"v2":     withRSV(sig, nil, nil, 2),
		"v3":     withRSV(sig, nil, nil, 3),
		"v4":     withRSV(sig, nil, nil, v+4),
		"v5":     withRSV(sig, nil, nil, 5),
		"v6":     withRSV(sig, nil, nil, 6),
		"v7":     withRSV(sig, nil, nil, 7),
		"v27":    withRSV(sig, nil, nil, 27),
		"v28":    withRSV(sig, nil, nil, 28),
		"r_zero": withRSV(sig, big.NewInt(0), nil, v),
		"s_zero": withRSV(sig, nil, big.NewInt(0), v),
		"r_n":    withRSV(sig, secpN, nil, v),
		"s_n":    withRSV(sig, nil, secpN, v),
		"r_max":  withRSV(sig, max256, nil, v),
	}
	for name, s := range fails {
		if _, err := RecoverDataSigner(data, s); err == nil {
			t.Errorf("%s: recovered", name)
		}
	}
	// V flipped recovers some other key; S = n-1 is in range.
	if a, err := RecoverDataSigner(data, withRSV(sig, nil, nil, v^1)); err != nil || a == Address(k) {
		t.Errorf("v flipped: %x %v", a, err)
	}
	if _, err := RecoverDataSigner(data, withRSV(sig, nil, nm1, v)); err != nil {
		t.Errorf("S = n-1: %v", err)
	}
}

// Covers: WBFT-CRYPTO-015, WBFT-CRYPTO-016
func TestCheckValidatorSignature(t *testing.T) {
	k := key0(t)
	sig, _ := SignData([]byte("m"), k)
	member := func(a types.Address) bool { return a == Address(k) }
	if a, err := CheckValidatorSignature(member, []byte("m"), sig); err != nil || a != Address(k) {
		t.Errorf("member: %x %v", a, err)
	}
	if _, err := CheckValidatorSignature(func(types.Address) bool { return false }, []byte("m"), sig); !errors.Is(err, ErrUnauthorizedAddress) {
		t.Errorf("non-member: %v", err)
	}
	if _, err := CheckValidatorSignature(member, []byte("m"), sig[:64]); err == nil || errors.Is(err, ErrUnauthorizedAddress) {
		t.Errorf("recovery error not propagated: %v", err)
	}
	if err := CheckSigner([]byte("m"), sig, types.Address{1}); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("other signer: %v", err)
	}
}

func TestPrivateKeyBounds(t *testing.T) {
	for _, b := range [][]byte{make([]byte, 32), secpN.Bytes(), make([]byte, 31)} {
		if _, err := PrivateKeyFromBytes(b); err == nil {
			t.Errorf("key %x accepted", b)
		}
	}
	one := make([]byte, 32)
	one[31] = 1
	k, err := PrivateKeyFromBytes(one)
	if err != nil || hex.EncodeToString(PrivateKeyBytes(k)) != hex.EncodeToString(one) {
		t.Errorf("key 1: %v", err)
	}
}
