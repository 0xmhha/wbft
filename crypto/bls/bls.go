package bls

import (
	"crypto/subtle"
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

// Lengths of the encodings.
//
// Spec: WBFT-TYPE-004
const (
	SecretKeyLength = 32 // big-endian scalar
	PublicKeyLength = 48 // compressed G1 point
	SignatureLength = 96 // compressed G2 point
)

// DST is the hash-to-curve domain separation tag of the ciphersuite
// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_.
var DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// Errors. The texts are informative.
var (
	ErrInvalidIKM         = errors.New("bls: key material shorter than 32 bytes")
	ErrZeroKey            = errors.New("bls: zero secret key")
	ErrSecretKey          = errors.New("bls: invalid secret key")
	ErrPublicKeyLength    = errors.New("bls: public key must be 48 bytes")
	ErrPublicKeyEncoding  = errors.New("bls: could not unmarshal bytes into public key")
	ErrInfinitePubKey     = errors.New("bls: received an infinite public key") // also a key outside the subgroup
	ErrSignatureLength    = errors.New("bls: signature must be 96 bytes")
	ErrSignatureEncoding  = errors.New("bls: could not unmarshal bytes into signature")
	ErrSignatureGroup     = errors.New("bls: signature not in group")
	ErrNoPublicKeys       = errors.New("bls: nil or empty public keys")
	ErrAggregateSignature = errors.New("bls: provided signatures fail the group check and cannot be compressed")
)

// SecretKey is a BLS secret key.
type SecretKey struct{ s blst.SecretKey }

// PublicKey is a decoded and validated BLS public key (G1). An aggregate
// public key may be the point at infinity.
type PublicKey struct{ p blst.P1Affine }

// Signature is a decoded, subgroup-checked BLS signature (G2). It may be the
// point at infinity.
type Signature struct{ s blst.P2Affine }

// DeriveSecretKey is derive_bls_key(node_key): the IETF KeyGen with the
// 32-byte big-endian node private key as IKM, the salt
// "BLS-SIG-KEYGEN-SALT-", an empty key_info and L = 48.
//
// Spec: WBFT-CRYPTO-020
func DeriveSecretKey(nodeKey []byte) (*SecretKey, error) {
	sk := blst.KeyGen(nodeKey)
	if sk == nil {
		return nil, ErrInvalidIKM
	}
	if isZero(sk.Serialize()) {
		return nil, ErrZeroKey
	}
	return &SecretKey{s: *sk}, nil
}

// SecretKeyFromBytes decodes a 32-byte big-endian secret key. It rejects a
// value that is zero or not below the group order.
func SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	if len(b) != SecretKeyLength {
		return nil, ErrSecretKey
	}
	var s blst.SecretKey
	if s.Deserialize(b) == nil {
		return nil, ErrSecretKey
	}
	if isZero(b) {
		return nil, ErrZeroKey
	}
	return &SecretKey{s: s}, nil
}

func isZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// Bytes returns the 32-byte big-endian encoding of sk.
func (sk *SecretKey) Bytes() []byte { return sk.s.Serialize() }

// PublicKey returns sk·G1.
//
// Spec: WBFT-CRYPTO-021
func (sk *SecretKey) PublicKey() *PublicKey {
	var pk PublicKey
	pk.p.From(&sk.s)
	return &pk
}

// Sign returns sk·hash_to_G2(msg, DST). msg is signed as is, without prior
// hashing.
//
// Spec: WBFT-CRYPTO-025
func (sk *SecretKey) Sign(msg []byte) *Signature {
	var sig Signature
	sig.s.Sign(&sk.s, msg, DST)
	return &sig
}

// Bytes returns the 48-byte compressed encoding of pk.
//
// Spec: WBFT-CRYPTO-022
func (pk *PublicKey) Bytes() []byte { return pk.p.Compress() }

// Bytes returns the 96-byte compressed encoding of s.
//
// Spec: WBFT-CRYPTO-022
func (s *Signature) Bytes() []byte { return s.s.Compress() }

// DecodePublicKey decodes a 48-byte compressed public key. It rejects a
// non-canonical encoding (flag bits, a coordinate not below p, an x without
// a curve point), the point at infinity and a point outside the subgroup.
//
// Spec: WBFT-CRYPTO-023, WBFT-CRYPTO-056
func DecodePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyLength {
		return nil, ErrPublicKeyLength
	}
	var pk PublicKey
	if pk.p.Uncompress(b) == nil {
		return nil, ErrPublicKeyEncoding
	}
	if !pk.p.KeyValidate() {
		return nil, ErrInfinitePubKey
	}
	return &pk, nil
}

// DecodeSignature decodes a 96-byte compressed signature. It rejects a
// non-canonical encoding and a point outside the subgroup; the point at
// infinity decodes.
//
// Spec: WBFT-CRYPTO-024, WBFT-CRYPTO-056
func DecodeSignature(b []byte) (*Signature, error) {
	if len(b) != SignatureLength {
		return nil, ErrSignatureLength
	}
	var s Signature
	if s.s.Uncompress(b) == nil {
		return nil, ErrSignatureEncoding
	}
	if !s.s.SigValidate(false) {
		return nil, ErrSignatureGroup
	}
	return &s, nil
}

// Verify reports whether sig is a signature of msg under pk. It is false when
// pk is the point at infinity, and false for a signature equal to the point
// at infinity under any other key.
//
// Spec: WBFT-CRYPTO-026, WBFT-CRYPTO-055
func Verify(pk *PublicKey, msg []byte, sig *Signature) bool {
	return sig.s.Verify(false, &pk.p, false, msg, DST)
}

// AggregatePublicKeys decodes every key with DecodePublicKey and returns
// their sum. An empty list fails; a sum equal to the point at infinity is
// returned without error.
//
// Spec: WBFT-CRYPTO-028
func AggregatePublicKeys(pks [][]byte) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}
	ps := make([]*blst.P1Affine, 0, len(pks))
	for _, b := range pks {
		pk, err := DecodePublicKey(b)
		if err != nil {
			return nil, err
		}
		ps = append(ps, &pk.p)
	}
	var agg blst.P1Aggregate
	if !agg.Aggregate(ps, false) {
		return nil, ErrNoPublicKeys
	}
	return &PublicKey{p: *agg.ToAffine()}, nil
}

// AggregateSignatures returns the sum of the decompressed, subgroup-checked
// signatures. It fails if any input does not decode or is outside the
// subgroup. The sum of the empty list is the point at infinity.
//
// Spec: WBFT-CRYPTO-027
func AggregateSignatures(sigs [][]byte) (*Signature, error) {
	var agg blst.P2Aggregate
	if !agg.AggregateCompressed(sigs, true) {
		return nil, ErrAggregateSignature
	}
	return &Signature{s: *agg.ToAffine()}, nil
}
