package epoch

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// A-04 §6.8 "Shuffle vectors".
func TestShuffleVectors(t *testing.T) {
	seed := keccak.Sum256([]byte("wbft-spec-a04"))
	if hex.EncodeToString(seed[:]) != "f28e414632a7647b703bc5559648840eb265067bf241c4c7471284bd4b114c28" {
		t.Fatalf("seed %x", seed)
	}
	for count, want := range map[int][]int{
		1: {0}, 2: {1, 0}, 3: {1, 0, 2}, 4: {1, 2, 0, 3}, 5: {0, 3, 2, 4, 1}, 8: {4, 2, 5, 1, 0, 7, 6, 3},
	} {
		if got := Shuffle(count, seed); !slices.Equal(got, want) {
			t.Errorf("count %d: %v, want %v", count, got, want)
		}
	}
	if got := Shuffle(4, types.Hash{}); !slices.Equal(got, []int{2, 3, 0, 1}) {
		t.Errorf("zero seed: %v", got)
	}
	if _, err := ComputeShuffledIndex(4, 4, seed); !errors.Is(err, ErrShuffleOutOfBounds) {
		t.Errorf("index 4 of 4: %v", err)
	}
	if _, err := ComputeShuffledIndex(0, 0, seed); err == nil {
		t.Error("count 0 accepted")
	}
}

// The shuffle is a permutation.
func TestShuffleIsPermutation(t *testing.T) {
	for _, n := range []int{1, 2, 13, 100, 257} {
		for s := 0; s < 5; s++ {
			seed := keccak.Sum256([]byte(strconv.Itoa(n*100 + s)))
			got := Shuffle(n, seed)
			slices.Sort(got)
			for i, v := range got {
				if v != i {
					t.Fatalf("n=%d seed %d: not a permutation", n, s)
				}
			}
		}
	}
}

// SortCandidates orders candidates as the reference implementation orders
// them (internal/refsort and its fixture).
func TestSortCandidates(t *testing.T) {
	ex := []uint64{5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5}
	cs := make([]ScoredCandidate, len(ex))
	for i, d := range ex {
		cs[i] = ScoredCandidate{Power: 1, Diligence: d}
	}
	if got := SortCandidates(cs); !slices.Equal(got, []int{9, 7, 13, 3, 11, 5, 1, 8, 6, 0, 10, 4, 12, 2, 14}) {
		t.Errorf("example: %v", got)
	}
	b, err := os.ReadFile("../internal/refsort/testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Keys []uint64 `json:"keys"`
			Desc []int    `json:"desc"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	ties := 0
	for i, c := range f.Cases {
		cs := make([]ScoredCandidate, len(c.Keys))
		for j, k := range c.Keys {
			cs[j] = ScoredCandidate{Power: 1, Diligence: k}
		}
		if got := SortCandidates(cs); !slices.Equal(got, c.Desc) {
			t.Errorf("case %d: %v, want %v", i, got, c.Desc)
		}
		if len(c.Keys) >= 13 {
			ties++
		}
	}
	if ties == 0 {
		t.Fatal("no case with 13 or more candidates")
	}
	// Power ranks before diligence.
	if got := SortCandidates([]ScoredCandidate{{Power: 1, Diligence: 9}, {Power: 2, Diligence: 1}}); !slices.Equal(got, []int{1, 0}) {
		t.Errorf("power order: %v", got)
	}
}

// Covers: WBFT-EPOCH-023
func TestInitialEpochInfo(t *testing.T) {
	init := types.GenesisInit{Validators: []types.Address{{1}, {2}}, BLSPublicKeys: [][]byte{{0xa}, {0xb}}}
	ei, err := InitialEpochInfo(init)
	if err != nil {
		t.Fatal(err)
	}
	if len(ei.Candidates) != 2 || ei.Candidates[1].Diligence != 1_900_000 || !slices.Equal(ei.Validators, []uint32{0, 1}) {
		t.Errorf("genesis epoch info %+v", ei)
	}
	if _, err := InitialEpochInfo(types.GenesisInit{Validators: []types.Address{{1}}}); err == nil {
		t.Error("missing key accepted")
	}
}

// chain is a types.ChainReader over canonical headers.
type chain map[types.Hash]*types.Header

func (c chain) Head() *types.Header                     { return nil }
func (c chain) HeaderByHash(h types.Hash) *types.Header { return c[h] }
func (c chain) HasBlock(h types.Hash, i uint64) bool    { return c.Header(h, i) != nil }
func (c chain) Header(h types.Hash, i uint64) *types.Header {
	if x := c[h]; x != nil && x.Number.RefLow64() == i {
		return x
	}
	return nil
}
func (c chain) HeaderByNumber(i uint64) *types.Header {
	for _, h := range c { //wbft:unordered at most one header per number
		if h.Number.RefLow64() == i {
			return h
		}
	}
	return nil
}

func bitmap(idx ...uint32) *types.AggregatedSeal {
	var s types.SealerSet
	for _, i := range idx {
		s.SetSealer(i)
	}
	return &types.AggregatedSeal{Sealers: s, Signature: append([]byte{0xc0}, make([]byte, 95)...)}
}

// A-04 §6.8, epoch 1: the computation at e = 4 with the executed output of
// the specification, and the verification of an epoch block against it.
//
// Covers: WBFT-EPOCH-021, WBFT-HDR-132
func TestComputeNextEpochInfoWorkedExample(t *testing.T) {
	var v [5]types.Address
	for i := range v {
		k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("wbft-spec-a04-key-" + strconv.Itoa(i))))
		if err != nil {
			t.Fatal(err)
		}
		v[i] = ecdsa.Address(k)
	}
	if hex.EncodeToString(v[0][:]) != "1feec135252c6152a4404606aac45c4fd46e6321" {
		t.Fatalf("v0 = %x", v[0])
	}
	pol := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 4, ProposerPolicy: &pol}, nil,
		types.GenesisInit{Validators: v[:4], BLSPublicKeys: [][]byte{{0}, {1}, {2}, {3}}}, nil)
	genesisInfo, _ := InitialEpochInfo(cfg.Init)

	c := chain{}
	mk := func(n uint64, parent *types.Header, coinbase types.Address, prep, com *types.AggregatedSeal, ei *types.EpochInfo) *types.Header {
		num := types.HeightFromUint64(n)
		h := &types.Header{Number: num, Difficulty: big.NewInt(1), Coinbase: coinbase, Time: 1_700_000_000 + n,
			MixDigest: keccak.Sum256(num.Bytes())}
		if parent != nil {
			h.ParentHash = codec.BlockHash(parent)
		}
		x := &types.WBFTExtra{PrevPreparedSeal: prep, PrevCommittedSeal: com, GasTip: big.NewInt(0), EpochInfo: ei}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		return h
	}
	g := mk(0, nil, types.Address{}, nil, nil, genesisInfo)
	c[codec.BlockHash(g)] = g
	b1 := mk(1, g, v[0], nil, nil, nil)
	b2 := mk(2, b1, v[2], bitmap(0, 1, 2, 3), bitmap(0, 1, 2), nil)
	b3 := mk(3, b2, v[3], bitmap(0, 1, 2, 3), bitmap(0, 1, 2, 3), nil)
	for _, h := range []*types.Header{b1, b2, b3} {
		c[codec.BlockHash(h)] = h
	}
	e := mk(4, b3, v[0], bitmap(0, 1, 2), bitmap(0, 1, 2), nil)
	if hex.EncodeToString(e.MixDigest[:]) != "f343681465b9efe82c933c3e8748c70cb8aa06539c361de20f72eac04e766393" {
		t.Fatalf("seed %x", e.MixDigest)
	}
	var cands []types.CandidateEntry
	for i, a := range v {
		cands = append(cands, types.CandidateEntry{Addr: a, BLSPublicKey: []byte{byte(0x10 + i)}})
	}
	ei, err := ComputeNextEpochInfo(c, cfg, e, cands)
	if err != nil {
		t.Fatal(err)
	}
	wantD := []uint64{1_888_750, 1_832_500, 1_898_125, 1_870_000, 1_900_000}
	for i, cd := range ei.Candidates {
		if cd.Addr != v[i] || cd.Diligence != wantD[i] {
			t.Errorf("candidate %d: %x %d, want %d", i, cd.Addr, cd.Diligence, wantD[i])
		}
	}
	if !slices.Equal(ei.Validators, []uint32{3, 1, 4, 0, 2}) {
		t.Errorf("validators %v", ei.Validators)
	}
	if len(ei.BLSPublicKeys) != 5 || ei.BLSPublicKeys[0][0] != 0x13 {
		t.Errorf("keys %x", ei.BLSPublicKeys)
	}

	// Verification accepts the computed value and rejects a change.
	withInfo := func(info *types.EpochInfo) *types.Header {
		h := e.Copy()
		x, _ := codec.DecodeExtra(h)
		x.EpochInfo = info
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		return h
	}
	if err := VerifyEpochInfo(c, cfg, withInfo(ei), cands); err != nil {
		t.Errorf("verify computed info: %v", err)
	}
	bad := ei.Copy()
	bad.Candidates[1].Diligence++
	if err := VerifyEpochInfo(c, cfg, withInfo(bad), cands); !errors.Is(err, ErrEpochInfoMismatch) {
		t.Errorf("verify changed diligence: %v", err)
	}
	if err := VerifyEpochInfo(c, cfg, e, cands); !errors.Is(err, validator.ErrEpochInfoNil) {
		t.Errorf("epoch block without EpochInfo: %v", err)
	}
	// Every difference of the three lists makes the block invalid.
	for name, mut := range map[string]func(x *types.EpochInfo){
		"candidate address":    func(x *types.EpochInfo) { x.Candidates[4].Addr[0] ^= 1 },
		"candidate dropped":    func(x *types.EpochInfo) { x.Candidates = x.Candidates[:4] },
		"candidate added":      func(x *types.EpochInfo) { x.Candidates = append(x.Candidates, x.Candidates[0]) },
		"validator index":      func(x *types.EpochInfo) { x.Validators[0], x.Validators[1] = x.Validators[1], x.Validators[0] },
		"validator dropped":    func(x *types.EpochInfo) { x.Validators = x.Validators[:4] },
		"key byte":             func(x *types.EpochInfo) { x.BLSPublicKeys[2] = []byte{0x7f} },
		"key dropped":          func(x *types.EpochInfo) { x.BLSPublicKeys = x.BLSPublicKeys[:4] },
		"key added":            func(x *types.EpochInfo) { x.BLSPublicKeys = append(x.BLSPublicKeys, []byte{1}) },
		"key longer than sent": func(x *types.EpochInfo) { x.BLSPublicKeys[0] = append(x.BLSPublicKeys[0], 0) },
	} {
		x := ei.Copy()
		mut(x)
		if err := VerifyEpochInfo(c, cfg, withInfo(x), cands); !errors.Is(err, ErrEpochInfoMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A candidate without a key stays a candidate but is not a validator.
	cands[2].BLSPublicKey = nil
	ei, err = ComputeNextEpochInfo(c, cfg, e, cands)
	if err != nil {
		t.Fatal(err)
	}
	if len(ei.Candidates) != 5 || slices.Contains(ei.Validators, 2) || len(ei.Validators) != 4 {
		t.Errorf("without key: %+v", ei.Validators)
	}

	// A block that is not an epoch block has no EpochInfo.
	if ei, err := ComputeNextEpochInfo(c, cfg, b3, cands); err != nil || ei != nil {
		t.Errorf("non-epoch block: %v %v", ei, err)
	}
}

// The genesis extra built from the configuration: empty vanity and reveal,
// zero rounds, no seals, the gas tip (INITIAL_GAS_TIP when absent) and the
// initial EpochInfo.
//
// Covers: WBFT-ENC-060
func TestGenesisExtra(t *testing.T) {
	init := types.GenesisInit{Validators: []types.Address{{1}, {2}}, BLSPublicKeys: [][]byte{{0xa}, {0xb}}}
	want, _ := InitialEpochInfo(init)
	for _, tt := range []struct {
		tip  *big.Int
		want uint64
	}{{nil, types.InitialGasTip}, {big.NewInt(0), 0}, {big.NewInt(5), 5}} {
		b, err := GenesisExtra(init, tt.tip)
		if err != nil {
			t.Fatal(err)
		}
		x, err := codec.DecodeExtraBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(x.VanityData) != 0 || len(x.RandaoReveal) != 0 || x.PrevRound != 0 || x.Round != 0 ||
			x.PrevPreparedSeal != nil || x.PrevCommittedSeal != nil || x.PreparedSeal != nil || x.CommittedSeal != nil {
			t.Errorf("tip %v: fields %+v", tt.tip, x)
		}
		if x.GasTip == nil || x.GasTip.Uint64() != tt.want {
			t.Errorf("tip %v: gas tip %v, want %d", tt.tip, x.GasTip, tt.want)
		}
		if x.EpochInfo == nil || !slices.Equal(x.EpochInfo.Validators, want.Validators) ||
			!slices.Equal(x.EpochInfo.Candidates, want.Candidates) || len(x.EpochInfo.BLSPublicKeys) != 2 {
			t.Errorf("tip %v: epoch info %+v", tt.tip, x.EpochInfo)
		}
	}
	if _, err := GenesisExtra(init, big.NewInt(-1)); err == nil {
		t.Error("negative gas tip encoded")
	}
	if _, err := GenesisExtra(types.GenesisInit{Validators: []types.Address{{1}}}, nil); err == nil {
		t.Error("validator without key accepted")
	}
}
