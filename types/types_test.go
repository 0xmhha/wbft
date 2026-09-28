package types

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"slices"
	"testing"
)

func two64() *big.Int { return new(big.Int).Lsh(big.NewInt(1), 64) }

// The truncating accessors equal big.Int.Uint64 and Int64 at 2^64 + s and
// k·2^64 (height-handling.md section 2).
func TestTruncation(t *testing.T) {
	cases := []*big.Int{
		big.NewInt(0), big.NewInt(1), new(big.Int).SetUint64(math.MaxUint64),
		two64(), new(big.Int).Add(two64(), big.NewInt(5)),
		new(big.Int).Mul(two64(), big.NewInt(3)),
		new(big.Int).Add(new(big.Int).Mul(two64(), big.NewInt(7)), big.NewInt(math.MaxInt64)),
		new(big.Int).SetUint64(1 << 63),
	}
	for _, b := range cases {
		h := MustHeightFromBig(b)
		if h.RefLow64() != b.Uint64() || h.RefLowInt64() != b.Int64() {
			t.Errorf("%s: %d %d", b, h.RefLow64(), h.RefLowInt64())
		}
		r, err := RoundFromBig(b)
		if err != nil {
			t.Fatal(err)
		}
		if r.RefLow64() != b.Uint64() || r.RefLow32() != uint32(b.Uint64()) {
			t.Errorf("round %s", b)
		}
		if h.String() != b.String() || h.Big().Cmp(b) != 0 {
			t.Errorf("full value of %s", b)
		}
	}
	if _, err := HeightFromBig(big.NewInt(-1)); err == nil {
		t.Error("negative height accepted")
	}
	// Round 2^32 + 3 is stored as 3 in the header fields.
	r, _ := RoundFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(3)))
	if r.RefLow32() != 3 {
		t.Errorf("RefLow32 %d", r.RefLow32())
	}
}

func TestHeightArithmetic(t *testing.T) {
	var zero Height
	if !zero.IsZero() || zero.String() != "0" || len(zero.Bytes()) != 0 {
		t.Error("zero value is not 0")
	}
	h := HeightFromUint64(math.MaxUint64).AddUint64(1)
	if h.Cmp(MustHeightFromBig(two64())) != 0 || h.IsUint64() {
		t.Errorf("MaxUint64 + 1 = %s", h)
	}
	if _, ok := HeightFromUint64(1).Sub(HeightFromUint64(2)); ok {
		t.Error("negative difference")
	}
	d, ok := h.Sub(HeightFromUint64(1))
	if !ok || d.RefLow64() != math.MaxUint64 {
		t.Errorf("sub %s", d)
	}
	v1 := View{Sequence: HeightFromUint64(2), Round: RoundFromUint64(9)}
	v2 := View{Sequence: HeightFromUint64(3), Round: RoundFromUint64(0)}
	if v1.Cmp(v2) >= 0 || v2.Cmp(v1) <= 0 || v1.Cmp(v1) != 0 {
		t.Error("view order")
	}
}

func u64(v uint64) *uint64 { return &v }

// A-01 §6.6.
func TestConfigAtWorkedExample(t *testing.T) {
	cfg := NewConfig(
		WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 10, ProposerPolicy: u64(0)},
		[]Transition{
			{Block: big.NewInt(200), WBFT: &WBFTParams{BlockPeriodSeconds: 2, MaxRequestTimeoutSeconds: u64(30)}},
			{Block: big.NewInt(100), WBFT: &WBFTParams{EpochLength: 20, ProposerPolicy: u64(1)}},
			{Block: big.NewInt(300), WBFT: &WBFTParams{MaxRequestTimeoutSeconds: u64(0)}},
		}, GenesisInit{}, nil)
	tests := []struct {
		n                      uint64
		rt, bp, epoch, pol, mx uint64
	}{
		{0, 2000, 1, 10, 0, 0}, {99, 2000, 1, 10, 0, 0},
		{100, 2000, 1, 20, 1, 0}, {199, 2000, 1, 20, 1, 0},
		{200, 2000, 2, 20, 1, 30}, {299, 2000, 2, 20, 1, 30},
		{300, 2000, 2, 20, 1, 0}, {1000000, 2000, 2, 20, 1, 0},
	}
	for _, tt := range tests {
		p := cfg.ConfigAt(HeightFromUint64(tt.n))
		if p.RequestTimeoutMs != tt.rt || p.BlockPeriodSeconds != tt.bp || p.EpochLength != tt.epoch ||
			p.ProposerPolicy == nil || p.ProposerPolicy.ID != tt.pol || p.MaxRequestTimeoutSeconds != tt.mx {
			t.Errorf("config_at(%d) = %+v", tt.n, p)
		}
	}
	// allowedFutureBlockTime comes from the base configuration only.
	cfg = NewConfig(WBFTParams{AllowedFutureBlockTime: 5, EpochLength: 10},
		[]Transition{{Block: big.NewInt(2), WBFT: &WBFTParams{AllowedFutureBlockTime: 30}}}, GenesisInit{}, nil)
	if p := cfg.ConfigAt(HeightFromUint64(3)); p.AllowedFutureBlockTime != 5 {
		t.Errorf("allowed future block time %d", p.AllowedFutureBlockTime)
	}
	// The request timeout product wraps modulo 2^64.
	cfg = NewConfig(WBFTParams{RequestTimeoutSeconds: 18446744073709552}, nil, GenesisInit{}, nil)
	want := new(big.Int).Mul(big.NewInt(18446744073709552), big.NewInt(1000))
	want.Mod(want, two64())
	if got := cfg.ConfigAt(HeightFromUint64(0)).RequestTimeoutMs; got != want.Uint64() {
		t.Errorf("wrapped timeout %d", got)
	}
}

// refsortFixture is the fixture of internal/refsort.
type refsortFixture struct {
	Cases []struct {
		Keys []uint64 `json:"keys"`
		Asc  []int    `json:"asc"`
	} `json:"cases"`
}

// SortTransitions orders transitions as the reference implementation orders
// them (internal/refsort and its fixture).
func TestSortTransitionsMatchesReference(t *testing.T) {
	b, err := os.ReadFile("../internal/refsort/testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var f refsortFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	withTies := 0
	for i, c := range f.Cases {
		ts := make([]Transition, len(c.Keys))
		for j, k := range c.Keys {
			// The configuration index is kept in EpochLength to read the
			// order back.
			ts[j] = Transition{Block: new(big.Int).SetUint64(k), WBFT: &WBFTParams{EpochLength: uint64(j)}}
		}
		SortTransitions(ts)
		got := make([]int, len(ts))
		for j, tr := range ts {
			got[j] = int(tr.WBFT.EpochLength)
		}
		if !slices.Equal(got, c.Asc) {
			t.Errorf("case %d: got %v, want %v", i, got, c.Asc)
		}
		if len(c.Keys) >= 13 {
			withTies++
		}
	}
	if withTies == 0 {
		t.Fatal("no case with 13 or more entries")
	}
}

func TestSortTransitionsNilBlockLast(t *testing.T) {
	ts := []Transition{{Block: nil}, {Block: big.NewInt(5)}, {Block: big.NewInt(1)}}
	SortTransitions(ts)
	if ts[0].Block.Int64() != 1 || ts[1].Block.Int64() != 5 || ts[2].Block != nil {
		t.Errorf("order %v %v %v", ts[0].Block, ts[1].Block, ts[2].Block)
	}
	cfg := NewConfig(WBFTParams{EpochLength: 4}, ts, GenesisInit{}, nil)
	if err := cfg.CheckTransitions(); err == nil {
		t.Error("transition without block accepted by CheckTransitions")
	}
	if p := cfg.ConfigAt(HeightFromUint64(10)); p.EpochLength != 4 {
		t.Errorf("epoch length %d", p.EpochLength)
	}
}

func TestParseChainConfig(t *testing.T) {
	raw := `{"chainId": 8282, "anzeon": {"wbft": {"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": 10, "proposerPolicy": 0},
		"init": {"validators": ["0xaa5faa65e9cc0f74a85b6fdfb5f6991f5c094697"], "blsPublicKeys": ["0xaec493af8fa358a1c6f05499f2dd712721ade88c477d21b799d38e9b84582b6fbe4f4adc21e1e454bc37522eb3478b9b"]}},
		"transitions": [{"block": 5, "epochLength": 7}, {"block": 3}]}`
	cfg, err := ParseChainConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChainID.Int64() != 8282 || cfg.Base().RequestTimeoutMs != 2000 || cfg.Base().ProposerPolicy.ID != 0 {
		t.Errorf("base %+v", cfg.Base())
	}
	if len(cfg.Init.Validators) != 1 || len(cfg.Init.BLSPublicKeys[0]) != 48 {
		t.Error("init not parsed")
	}
	ts := cfg.Transitions()
	if ts[0].Block.Int64() != 3 || ts[0].WBFT != nil || ts[1].WBFT.EpochLength != 7 {
		t.Errorf("transitions %+v", ts)
	}
	if err := cfg.CheckTransitions(); err == nil {
		t.Error("transition without WBFT field accepted by CheckTransitions")
	}
	if _, err := ParseChainConfig([]byte(`{"anzeon": {}}`)); err == nil {
		t.Error("configuration without anzeon.wbft accepted")
	}
	if _, err := ParseChainConfig([]byte(`{"anzeon": {"wbft": {}, "init": {"blsPublicKeys": ["aa"]}}}`)); err == nil {
		t.Error("key without 0x accepted")
	}
}

// Covers: WBFT-PROP-002
func TestProposerOf(t *testing.T) {
	h := &Header{Number: HeightFromUint64(0), Coinbase: Address{1}}
	if ProposerOf(h) != (Address{}) {
		t.Error("genesis proposer is not zero")
	}
	h.Number = HeightFromUint64(1)
	if ProposerOf(h) != (Address{1}) {
		t.Error("proposer is not the coinbase")
	}
}

// View comparison orders by sequence first and by round only for equal
// sequences, including heights and rounds above 2^64.
//
// Covers: WBFT-TYPE-020
func TestViewCmp(t *testing.T) {
	big64 := func(add int64) Height {
		h, err := HeightFromBig(new(big.Int).Add(two64(), big.NewInt(add)))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	view := func(s Height, r uint64) View { return View{Sequence: s, Round: RoundFromUint64(r)} }
	for _, tt := range []struct {
		a, b View
		want int
	}{
		{view(HeightFromUint64(5), 0), view(HeightFromUint64(5), 0), 0},
		{view(HeightFromUint64(5), 1), view(HeightFromUint64(5), 0), 1},
		{view(HeightFromUint64(5), 0), view(HeightFromUint64(5), 1), -1},
		// A higher sequence wins over any round.
		{view(HeightFromUint64(6), 0), view(HeightFromUint64(5), math.MaxUint64), 1},
		{view(HeightFromUint64(4), math.MaxUint64), view(HeightFromUint64(5), 0), -1},
		// No truncation: 2^64 + 1 is above 1.
		{view(big64(1), 0), view(HeightFromUint64(1), 7), 1},
		{view(big64(0), 3), view(big64(0), 2), 1},
	} {
		if got := tt.a.Cmp(tt.b); got != tt.want {
			t.Errorf("%v/%v Cmp %v/%v = %d, want %d", tt.a.Sequence, tt.a.Round, tt.b.Sequence, tt.b.Round, got, tt.want)
		}
		if got := tt.b.Cmp(tt.a); got != -tt.want {
			t.Errorf("reverse of %v/%v: %d", tt.a.Sequence, tt.a.Round, got)
		}
	}
}

// A configuration without anzeon.wbft.proposerPolicy is refused for start-up
// even when a transition sets a policy, since heights before the transition
// and height 0 use the base policy.
//
// Covers: WBFT-PARAM-032, WBFT-PARAM-034
func TestCheckProposerPolicy(t *testing.T) {
	pol := uint64(1)
	withTransition := NewConfig(WBFTParams{EpochLength: 10}, []Transition{{Block: big.NewInt(5), WBFT: &WBFTParams{ProposerPolicy: &pol}}}, GenesisInit{}, nil)
	var e *ErrConfig
	if err := withTransition.CheckProposerPolicy(); !errors.As(err, &e) || e.Field != "anzeon.wbft.proposerPolicy" {
		t.Errorf("missing base policy: %v", err)
	}
	for _, id := range []uint64{0, 1, 7} {
		if err := NewConfig(WBFTParams{ProposerPolicy: &id}, nil, GenesisInit{}, nil).CheckProposerPolicy(); err != nil {
			t.Errorf("policy %d: %v", id, err)
		}
	}
}

// The genesis validators are refused unless there is at least one and the
// numbers of validators and BLS keys are equal.
//
// Covers: WBFT-EPOCH-024
func TestGenesisInitCheck(t *testing.T) {
	a, k := Address{1}, []byte{0xa}
	for name, tt := range map[string]struct {
		init GenesisInit
		ok   bool
	}{
		"one":        {GenesisInit{Validators: []Address{a}, BLSPublicKeys: [][]byte{k}}, true},
		"two":        {GenesisInit{Validators: []Address{a, {2}}, BLSPublicKeys: [][]byte{k, k}}, true},
		"empty":      {GenesisInit{}, false},
		"keys only":  {GenesisInit{BLSPublicKeys: [][]byte{k}}, false},
		"fewer keys": {GenesisInit{Validators: []Address{a, {2}}, BLSPublicKeys: [][]byte{k}}, false},
		"more keys":  {GenesisInit{Validators: []Address{a}, BLSPublicKeys: [][]byte{k, k}}, false},
	} {
		if err := tt.init.Check(); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tt.ok)
		}
	}
}
