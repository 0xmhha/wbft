package privval

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func testKey(i int) []byte {
	return keccak.Sum256Bytes([]byte("wbft-privval-test-key-" + strconv.Itoa(i)))
}

func newTestSigner(t *testing.T, fs fsys.FS) *FileSigner {
	t.Helper()
	if err := fs.MkdirAll("/pv", 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySigner(fs, nil, testKey(0), "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func reopen(t *testing.T, fs fsys.FS) *FileSigner {
	t.Helper()
	s, err := NewKeySigner(fs, nil, testKey(0), "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func view(seq, round uint64) types.View {
	return types.View{Sequence: types.HeightFromUint64(seq), Round: types.RoundFromUint64(round)}
}

func rp(r uint64) *types.Round { x := types.RoundFromUint64(r); return &x }

func vote(code codec.Code, v types.View, digest byte) VoteRequest {
	d := types.Hash{digest}
	return VoteRequest{Msg: &codec.Message{Code: code, View: v, Digest: d}, SealData: append([]byte("seal"), digest)}
}

func proposal(seq uint64, tag byte) *types.Block {
	extra, _ := codec.EncodeExtra(&types.WBFTExtra{VanityData: make([]byte, types.ExtraVanity), RandaoReveal: []byte{}})
	return &types.Block{Header: &types.Header{
		ParentHash: types.Hash{tag}, UncleHash: types.EmptyUncleHash, Difficulty: big.NewInt(1),
		Number: types.HeightFromUint64(seq), GasLimit: 1, Time: 1, Extra: extra,
	}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

func preprepare(seq, round uint64, tag byte) VoteRequest {
	return VoteRequest{Msg: &codec.Message{Code: codec.CodePreprepare, View: view(seq, round), Proposal: proposal(seq, tag)}}
}

func roundChange(seq, round uint64, prepared *types.Round, tag byte) VoteRequest {
	m := &codec.Message{Code: codec.CodeRoundChange, View: view(seq, round)}
	if prepared != nil {
		m.PreparedRound = prepared
		m.PreparedBlock = proposal(seq, tag)
		m.PreparedDigest = codec.BlockHash(m.PreparedBlock.Header)
	}
	return VoteRequest{Msg: m}
}

// verify checks that sig is the signature of the node key over the message
// with the seal.
func verify(t *testing.T, req VoteRequest, sig VoteSignature) {
	t.Helper()
	c := *req.Msg
	c.Seal = sig.Seal
	c.Signature = sig.Signature
	p, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.PrivateKeyFromBytes(testKey(0))
	if err := ecdsa.CheckSigner(p, sig.Signature, ecdsa.Address(k)); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if req.SealData != nil {
		bk, _ := bls.DeriveSecretKey(testKey(0))
		s, err := bls.DecodeSignature(sig.Seal)
		if err != nil || !bls.Verify(bk.PublicKey(), req.SealData, s) {
			t.Fatalf("seal does not verify: %v", err)
		}
	}
}

func mustSign(t *testing.T, s *FileSigner, req VoteRequest) VoteSignature {
	t.Helper()
	sig, err := s.SignVote(req)
	if err != nil {
		t.Fatalf("sign %d %v: %v", req.Msg.Code, req.Msg.View, err)
	}
	verify(t, req, sig)
	return sig
}

func refused(t *testing.T, s *FileSigner, req VoteRequest, want error) {
	t.Helper()
	if _, err := s.SignVote(req); !errors.Is(err, want) {
		t.Fatalf("sign %d %v: got %v, want %v", req.Msg.Code, req.Msg.View, err, want)
	}
}

// Each cell of the rule table, and the same cells after reopening the state.
func TestSignRules(t *testing.T) {
	for _, restart := range []bool{false, true} {
		fs := fsys.NewMem()
		s := newTestSigner(t, fs)
		next := func() *FileSigner {
			if restart {
				return reopen(t, fs)
			}
			return s
		}
		// PREPARE and COMMIT: same payload -> stored; different -> refused.
		for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
			a := mustSign(t, s, vote(code, view(10, 0), 1))
			s = next()
			b := mustSign(t, s, vote(code, view(10, 0), 1))
			if !b.Reused || !bytes.Equal(a.Signature, b.Signature) || !bytes.Equal(a.Seal, b.Seal) {
				t.Fatalf("code %d: re-sign did not return the stored signature", code)
			}
			refused(t, s, vote(code, view(10, 0), 2), ErrDoubleSign)
			mustSign(t, s, vote(code, view(10, 1), 2)) // another round
		}
		// PRE-PREPARE: round 0 and later rounds alike.
		for _, r := range []uint64{0, 3} {
			a := mustSign(t, s, preprepare(10, r, 1))
			s = next()
			if b := mustSign(t, s, preprepare(10, r, 1)); !b.Reused || !bytes.Equal(a.Signature, b.Signature) {
				t.Fatal("PRE-PREPARE re-sign")
			}
			refused(t, s, preprepare(10, r, 2), ErrDoubleSign)
		}
		// ROUND-CHANGE: the COMMIT of round 1 at 10 sets the lock floor.
		refused(t, s, roundChange(10, 2, nil, 0), ErrDoubleSign)
		refused(t, s, roundChange(10, 2, rp(0), 1), ErrDoubleSign)
		a := mustSign(t, s, roundChange(10, 2, rp(1), 1))
		s = next()
		if b := mustSign(t, s, roundChange(10, 2, rp(1), 1)); !b.Reused || !bytes.Equal(a.Signature, b.Signature) {
			t.Fatal("ROUND-CHANGE re-send")
		}
		// A higher prepared round replaces; a lower one is refused.
		mustSign(t, s, roundChange(10, 2, rp(2), 3))
		s = next()
		refused(t, s, roundChange(10, 2, rp(1), 1), ErrDoubleSign)
		// Another sequence without COMMIT: none, then a prepared round.
		mustSign(t, s, roundChange(11, 1, nil, 0))
		mustSign(t, s, roundChange(11, 1, rp(0), 1))
		refused(t, s, roundChange(11, 1, nil, 0), ErrDoubleSign)
		// Height rule: below the highest height only the same payload.
		s = next()
		refused(t, s, vote(codec.CodePrepare, view(10, 5), 1), ErrDoubleSign)
		if b := mustSign(t, s, vote(codec.CodePrepare, view(10, 0), 1)); !b.Reused {
			t.Fatal("re-sign below the highest height")
		}
		// Records two heights below the highest are summarized away.
		mustSign(t, s, vote(codec.CodePrepare, view(12, 0), 1))
		s = next()
		refused(t, s, vote(codec.CodePrepare, view(10, 0), 1), ErrDoubleSign)
		if h, ok := s.LastHeight(); !ok || h.CmpUint64(12) != 0 {
			t.Fatalf("last height %v %v", h, ok)
		}
	}
}

func TestRandao(t *testing.T) {
	s := newTestSigner(t, fsys.NewMem())
	a, err := s.SignRandao(big.NewInt(8282), types.HeightFromUint64(5))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.SignRandao(big.NewInt(8282), types.HeightFromUint64(5))
	if !bytes.Equal(a, b) {
		t.Fatal("randao reveal is not deterministic")
	}
	if err := ecdsa.CheckSigner(codec.RandaoData(big.NewInt(8282), types.HeightFromUint64(5)), a, s.Address()); err != nil {
		t.Fatal(err)
	}
	// The floor does not apply to randao.
	s2 := newTestSigner(t, fsys.NewMem())
	if err := s2.InitSignFloor(types.HeightFromUint64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.SignRandao(big.NewInt(1), types.HeightFromUint64(50)); err != nil {
		t.Fatal(err)
	}
}

func TestSignFloor(t *testing.T) {
	fs := fsys.NewMem()
	s := newTestSigner(t, fs)
	if !s.Empty() {
		t.Fatal("new state is not empty")
	}
	if err := s.InitSignFloor(types.HeightFromUint64(20)); err != nil {
		t.Fatal(err)
	}
	if s.Empty() {
		t.Fatal("a floor is not empty")
	}
	s = reopen(t, fs)
	if h, ok := s.SignFloor(); !ok || h.CmpUint64(20) != 0 {
		t.Fatalf("floor after reopen: %v %v", h, ok)
	}
	for _, req := range []VoteRequest{
		preprepare(20, 0, 1), vote(codec.CodePrepare, view(20, 0), 1),
		vote(codec.CodeCommit, view(20, 3), 1), roundChange(20, 1, nil, 0),
		vote(codec.CodePrepare, view(7, 0), 1),
	} {
		refused(t, s, req, ErrBelowSignFloor)
	}
	if h, ok := s.LastHeight(); !ok || h.CmpUint64(20) != 0 {
		t.Fatalf("H_sign with a floor: %v", h)
	}
	// The floor can be cleared while nothing is signed.
	if err := s.ClearSignFloor(); err != nil {
		t.Fatal(err)
	}
	if !reopen(t, fs).Empty() {
		t.Fatal("cleared floor persisted")
	}
	if err := s.InitSignFloor(types.HeightFromUint64(20)); err != nil {
		t.Fatal(err)
	}
	for _, req := range []VoteRequest{
		preprepare(21, 0, 1), vote(codec.CodePrepare, view(21, 0), 1),
		vote(codec.CodeCommit, view(21, 0), 1), roundChange(21, 1, rp(0), 1),
	} {
		mustSign(t, s, req)
	}
	if err := s.ClearSignFloor(); !errors.Is(err, ErrSignStateNotEmpty) {
		t.Fatalf("clear after a signature: %v", err)
	}
	if err := s.InitSignFloor(types.HeightFromUint64(30)); !errors.Is(err, ErrSignStateNotEmpty) {
		t.Fatalf("init after a signature: %v", err)
	}
}

func TestDamagedState(t *testing.T) {
	fs := fsys.NewMem()
	s := newTestSigner(t, fs)
	mustSign(t, s, vote(codec.CodePrepare, view(3, 0), 1))
	good, _ := fs.ReadFile("/pv/state")
	cases := map[string][]byte{
		"empty":     {},
		"format":    append([]byte{9}, good[1:]...),
		"truncated": good[:len(good)/2],
		"garbage":   append([]byte{stateFormat}, 0xff, 0x01),
	}
	for name, data := range cases {
		c := fsys.NewMem()
		_ = c.MkdirAll("/pv", 0o700)
		f, _ := c.OpenFile("/pv/state", os.O_WRONLY|os.O_CREATE, 0o600)
		_, _ = f.Write(data)
		_ = f.Close()
		_, err := NewKeySigner(c, nil, testKey(0), "/pv/state")
		if !errors.Is(err, ErrStateCorrupt) && !errors.Is(err, ErrStateFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeyFile(t *testing.T) {
	key := testKey(1)
	hexKey := FormatKeyFile(key)
	for _, ok := range [][]byte{hexKey, append(hexKey, '\n'), append(hexKey, '\r', '\n')} {
		got, err := ParseKeyFile(ok)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range [][]byte{hexKey[:63], append(hexKey, '\n', '\n', '\n'), append(hexKey, 'x'), append([]byte("zz"), hexKey[2:]...), {}} {
		if _, err := ParseKeyFile(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	fs := fsys.NewMem()
	_ = fs.MkdirAll("/k", 0o700)
	f, _ := fs.OpenFile("/k/nodekey", os.O_WRONLY|os.O_CREATE, 0o600)
	_, _ = f.Write(append(hexKey, '\n'))
	_ = f.Close()
	s, err := OpenFileSigner(Options{FS: fs}, "/k/nodekey", "/k/state")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.PrivateKeyFromBytes(key)
	bk, _ := bls.DeriveSecretKey(key)
	if s.Address() != ecdsa.Address(k) || !bytes.Equal(s.BLSPublicKey(), bk.PublicKey().Bytes()) {
		t.Fatal("key file identity")
	}
	// The operating-system signer reads the same format.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/nodekey", hexKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSigner(dir+"/nodekey", dir+"/state"); err != nil {
		t.Fatal(err)
	}
}

type crash struct{ at string }

// A crash before or after the state reaches the disk never lets the
// restarted signer sign a conflicting payload for a view it returned a
// signature for, and a signature is only returned after the state is
// durable.
func TestCrashAroundPersist(t *testing.T) {
	for _, point := range []string{faultpoint.PrivvalBeforePersist, faultpoint.PrivvalAfterPersist} {
		for seed := uint64(0); seed < 20; seed++ {
			fs := fsys.NewMem()
			_ = fs.MkdirAll("/pv", 0o700)
			rng := rand.New(rand.NewPCG(seed, 2))
			k := rng.IntN(6)
			hits := 0
			handler := func(name string) {
				if faultpoint.Enabled && name == point {
					if hits == k {
						panic(crash{at: name})
					}
					hits++
				}
			}
			s, err := NewKeySigner(fs, handler, testKey(0), "/pv/state")
			if err != nil {
				t.Fatal(err)
			}
			returned := map[string][]byte{}
			func() {
				defer func() {
					if r := recover(); r != nil {
						if _, ok := r.(crash); !ok {
							panic(r)
						}
					}
				}()
				for i := uint64(0); i < 6; i++ {
					req := vote(codec.CodePrepare, view(10+i, 0), 1)
					sig, err := s.SignVote(req)
					if err != nil {
						t.Fatal(err)
					}
					returned[req.Msg.View.Sequence.String()] = sig.Signature
				}
			}()
			fs.Crash(rng)
			s2 := reopen(t, fs)
			for seq := range returned { //wbft:unordered each entry is checked
				n, _ := strconv.ParseUint(seq, 10, 64)
				if _, err := s2.SignVote(vote(codec.CodePrepare, view(n, 0), 2)); err == nil {
					t.Fatalf("%s seed %d: conflicting PREPARE at %s signed after restart", point, seed, seq)
				}
			}
		}
	}
}
