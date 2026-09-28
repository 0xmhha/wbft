package bls

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/crypto/keccak"
)

// BLS12-381 base field modulus p and group order r (A-02 §1).
var (
	blsP, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
	blsR, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
)

func vectorSK(t *testing.T, i int) *SecretKey {
	t.Helper()
	sk, err := DeriveSecretKey(keccak.Sum256Bytes([]byte("wbft-spec-vector-key-" + string(rune('0'+i)))))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// A-02 §8.1.
func TestDerive(t *testing.T) {
	want := []struct{ sk, pk string }{
		{"35de7bc5d48c484e7b87e7b96ebf61d15ae225d6dd3fea0663c9291b5ac10f5a", "8eaaca1bbb29c07cb653b346e8434bb6b3bc63a4bb7c8dfea5c46bae2473646fe8041e3ff81da70bba7effda935a4576"},
		{"488c292335a8c97b4c228b4ba2d3e43c875ad2445e3331ff173b8630b47d65bc", "8a8f913a1bac306b3b1661fc78ce376a650341ce314f7c0f615fc7abf3722eb6c256046483c266d3e03ce82edbed13a3"},
		{"3d57e6be7c50f146643b268d185c00c1bf67708a590c8662ce976b14ee16fc64", "976a4cd50f07ad6fb3fc0a7a27a803212be7cf84b779d9a5562af81316187dec8ee319a0ce421c020dc1bf1faa494abe"},
		{"4dbb674eac4df7166edbdca4ef7a7f96a3e73be6935164e276a57a48360f8a47", "aa6b0cda839b65a5e2e556484ccb3d67fac59c1cc66ab2bf1b9160ecee30a0deb6dbbad04836ca99ceb74c225a0c184e"},
	}
	for i, w := range want {
		sk := vectorSK(t, i)
		if hex.EncodeToString(sk.Bytes()) != w.sk || hex.EncodeToString(sk.PublicKey().Bytes()) != w.pk {
			t.Errorf("key %d: %x %x", i, sk.Bytes(), sk.PublicKey().Bytes())
		}
	}
	if _, err := DeriveSecretKey(make([]byte, 31)); err == nil {
		t.Error("31-byte key material accepted")
	}
}

// A-02 §8.3.
func TestSignVerify(t *testing.T) {
	sk := vectorSK(t, 0)
	m := keccak.Sum256Bytes([]byte("wbft-bls"))
	sig := sk.Sign(m)
	want := "99578d7f3a838333dfeeb2a7ade9fa0e150e913fb852dac9606c06099b929079e2a0a89ed229fe40eb23d82c9511be2b161297f1a426a8fc5dcedd81f20783288897330bf58ad2e94098f6bc63a638547b72f35fb906e273f84f48e77c59066f"
	if hex.EncodeToString(sig.Bytes()) != want {
		t.Fatalf("signature %x", sig.Bytes())
	}
	pk := sk.PublicKey()
	if !Verify(pk, m, sig) {
		t.Fatal("valid signature does not verify")
	}
	if Verify(pk, keccak.Sum256Bytes([]byte("wbft-blt")), sig) {
		t.Error("signature verifies another message")
	}
	if Verify(vectorSK(t, 1).PublicKey(), m, sig) {
		t.Error("signature verifies under another key")
	}
	inf := append([]byte{0xc0}, make([]byte, 95)...)
	s, err := DecodeSignature(inf)
	if err != nil {
		t.Fatalf("infinity signature: %v", err)
	}
	if Verify(pk, m, s) {
		t.Error("infinity signature verifies")
	}
}

func TestDecodingRules(t *testing.T) {
	pk := vectorSK(t, 0).PublicKey().Bytes()
	sig := vectorSK(t, 0).Sign([]byte("x")).Bytes()
	flip := func(b []byte, mask byte) []byte { o := append([]byte(nil), b...); o[0] ^= mask; return o }
	pkBad := map[string][]byte{
		"infinity":         append([]byte{0xc0}, make([]byte, 47)...),
		"zero":             make([]byte, 48),
		"len47":            pk[:47],
		"len49":            append(append([]byte(nil), pk...), 0),
		"no_compression":   flip(pk, 0x80),
		"infinity_sign":    append([]byte{0xe0}, make([]byte, 47)...),
		"infinity_nonzero": append(append([]byte{0xc0}, make([]byte, 46)...), 1),
		"infinity_no_flag": append([]byte{0x40}, make([]byte, 47)...),
	}
	for name, b := range pkBad {
		if _, err := DecodePublicKey(b); err == nil {
			t.Errorf("public key %s decoded", name)
		}
	}
	if _, err := DecodePublicKey(flip(pk, 0x20)); err != nil {
		t.Errorf("negated public key: %v", err)
	}
	sigBad := map[string][]byte{
		"zero":             make([]byte, 96),
		"len95":            sig[:95],
		"no_compression":   flip(sig, 0x80),
		"infinity_sign":    append([]byte{0xe0}, make([]byte, 95)...),
		"infinity_nonzero": append(append([]byte{0xc0}, make([]byte, 94)...), 1),
	}
	for name, b := range sigBad {
		if _, err := DecodeSignature(b); err == nil {
			t.Errorf("signature %s decoded", name)
		}
		if _, err := AggregateSignatures([][]byte{b}); err == nil {
			t.Errorf("signature %s aggregated", name)
		}
	}
	// A coordinate plus p that still fits in 381 bits is rejected (the
	// search mirrors the vector generator: find such a key).
	found := false
	for i := 0; i < 64 && !found; i++ {
		b := vectorSKn(t, i).PublicKey().Bytes()
		x := new(big.Int).SetBytes(append([]byte{b[0] & 0x1f}, b[1:]...))
		x.Add(x, blsP)
		if x.BitLen() > 381 {
			continue
		}
		o := x.FillBytes(make([]byte, 48))
		o[0] |= b[0] & 0xe0
		if _, err := DecodePublicKey(o); err == nil {
			t.Error("public key with x + p decoded")
		}
		found = true
	}
	if !found {
		t.Skip("no key with x + p below 2^381 among the first keys")
	}
}

func vectorSKn(t *testing.T, i int) *SecretKey {
	t.Helper()
	sk, err := DeriveSecretKey(keccak.Sum256Bytes([]byte("wbft-rule-" + big.NewInt(int64(i)).String())))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestAggregation(t *testing.T) {
	msg := []byte("seal data")
	var sigs, pks [][]byte
	for i := 0; i < 3; i++ {
		sk := vectorSK(t, i)
		sigs = append(sigs, sk.Sign(msg).Bytes())
		pks = append(pks, sk.PublicKey().Bytes())
	}
	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	apk, err := AggregatePublicKeys(pks)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(apk, msg, agg) {
		t.Fatal("aggregate does not verify")
	}
	// The order of aggregation does not matter.
	rev, _ := AggregateSignatures([][]byte{sigs[2], sigs[0], sigs[1]})
	if !bytes.Equal(rev.Bytes(), agg.Bytes()) {
		t.Error("aggregation depends on order")
	}
	// Empty list: point at infinity; empty key list fails.
	empty, err := AggregateSignatures(nil)
	if err != nil || !bytes.Equal(empty.Bytes(), append([]byte{0xc0}, make([]byte, 95)...)) {
		t.Errorf("empty aggregate %x %v", empty.Bytes(), err)
	}
	if _, err := AggregatePublicKeys(nil); err == nil {
		t.Error("empty key list aggregated")
	}

	// Keys a, b, -(a+b) sum to infinity; no error, but nothing verifies
	// under the sum, not even the infinity signature.
	a := new(big.Int).SetBytes(vectorSK(t, 0).Bytes())
	b := new(big.Int).SetBytes(vectorSK(t, 1).Bytes())
	c := new(big.Int).Neg(new(big.Int).Add(a, b))
	c.Mod(c, blsR)
	skc, err := SecretKeyFromBytes(c.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	tri := [][]byte{pks[0], pks[1], skc.PublicKey().Bytes()}
	sum, err := AggregatePublicKeys(tri)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sum.Bytes(), append([]byte{0xc0}, make([]byte, 47)...)) {
		t.Fatalf("sum %x", sum.Bytes())
	}
	triSig, err := AggregateSignatures([][]byte{sigs[0], sigs[1], skc.Sign(msg).Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(triSig.Bytes(), empty.Bytes()) {
		t.Fatalf("signature sum %x", triSig.Bytes())
	}
	if Verify(sum, msg, triSig) {
		t.Error("infinity key verifies")
	}
}

func TestSecretKeyBounds(t *testing.T) {
	if _, err := SecretKeyFromBytes(make([]byte, 32)); err == nil {
		t.Error("zero key accepted")
	}
	if _, err := SecretKeyFromBytes(blsR.FillBytes(make([]byte, 32))); err == nil {
		t.Error("key equal to r accepted")
	}
	if _, err := SecretKeyFromBytes(make([]byte, 31)); err == nil {
		t.Error("short key accepted")
	}
}
