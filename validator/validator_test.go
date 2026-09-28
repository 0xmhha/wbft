package validator

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// quorumTable is the output of the reference for these sizes: the binary64
// bits of F, the quorum and the F+1 count (A-04 §2.2, validators/quorum).
var quorumTable = []struct {
	n      int
	fBits  uint64
	quorum int
	fPlus1 int
}{
	{0, 0xbfd5555555555555, 1, 0}, {1, 0x0000000000000000, 1, 1}, {2, 0x3fd5555555555555, 2, 1},
	{3, 0x3fe5555555555555, 3, 1}, {4, 0x3ff0000000000000, 3, 2}, {5, 0x3ff5555555555555, 4, 2},
	{6, 0x3ffaaaaaaaaaaaab, 5, 2}, {7, 0x4000000000000000, 5, 3}, {8, 0x4002aaaaaaaaaaab, 6, 3},
	{9, 0x4005555555555555, 7, 3}, {10, 0x4008000000000000, 7, 4}, {11, 0x400aaaaaaaaaaaab, 8, 4},
	{12, 0x400d555555555555, 9, 4}, {13, 0x4010000000000000, 9, 5}, {14, 0x4011555555555555, 10, 5},
	{15, 0x4012aaaaaaaaaaab, 11, 5}, {16, 0x4014000000000000, 11, 6}, {17, 0x4015555555555555, 12, 6},
	{18, 0x4016aaaaaaaaaaab, 13, 6}, {19, 0x4018000000000000, 13, 7}, {20, 0x4019555555555555, 14, 7},
	{21, 0x401aaaaaaaaaaaab, 15, 7}, {22, 0x401c000000000000, 15, 8}, {31, 0x4024000000000000, 21, 11},
	{64, 0x4035000000000000, 43, 22}, {100, 0x4040800000000000, 67, 34}, {101, 0x4040aaaaaaaaaaab, 68, 34},
	{102, 0x4040d55555555555, 69, 34}, {128, 0x40452aaaaaaaaaab, 86, 43}, {255, 0x40552aaaaaaaaaab, 171, 85},
	{256, 0x4055400000000000, 171, 86}, {1000, 0x4074d00000000000, 667, 334},
}

func TestQuorumTable(t *testing.T) {
	for _, r := range quorumTable {
		if got := math.Float64bits(FValue(r.n)); got != r.fBits {
			t.Errorf("F(%d) bits %#x, want %#x", r.n, got, r.fBits)
		}
		if got := QuorumSize(r.n); got != r.quorum {
			t.Errorf("QuorumSize(%d) = %d, want %d", r.n, got, r.quorum)
		}
		if got := FPlusOneThreshold(r.n); got != r.fPlus1 || !InFPlusOneWindow(got, r.n) {
			t.Errorf("F+1(%d) = %d, want %d", r.n, got, r.fPlus1)
		}
	}
}

// For n below 3·2^50 + 3 the binary64 quorum equals (2n) div 3 + 1, and the
// F+1 window holds exactly the integer threshold.
func TestQuorumIntegerForm(t *testing.T) {
	for n := 0; n <= 10000; n++ {
		if got, want := QuorumSize(n), 2*n/3+1; got != want {
			t.Fatalf("QuorumSize(%d) = %d, want %d", n, got, want)
		}
		th := FPlusOneThreshold(n)
		for c := th - 3; c <= th+3; c++ {
			if InFPlusOneWindow(c, n) != (c == th) {
				t.Fatalf("n=%d: window at %d", n, c)
			}
		}
	}
}

// The first sizes at which the binary64 forms differ from the integer
// forms (A-04 §2.1, WBFT-VAL-002 and WBFT-VAL-003).
func TestQuorumBoundaries(t *testing.T) {
	b := 3<<50 + 3
	for n, want := range map[int]int{b - 1: 2*(b-1)/3 + 1, b: 2 * b / 3, b + 1: 2*(b+1)/3 + 1} {
		if got := QuorumSize(n); got != want {
			t.Errorf("QuorumSize(%d) = %d, want %d", n, got, want)
		}
	}
	w := 1<<53 + 2
	th := FPlusOneThreshold(w)
	if InFPlusOneWindow(th, w) || !InFPlusOneWindow(th-1, w) {
		t.Errorf("n = 2^53 + 2: window does not hold threshold - 1")
	}
	for _, n := range []int{1 << 53, 1<<53 + 1} {
		if !InFPlusOneWindow(FPlusOneThreshold(n), n) {
			t.Errorf("n=%d: threshold outside the window", n)
		}
	}
}

func addr(i int) types.Address {
	var a types.Address
	big.NewInt(int64(0x1000 + i)).FillBytes(a[:])
	return a
}

func set(t *testing.T, n int, policy uint64) *Set {
	t.Helper()
	addrs := make([]types.Address, n)
	keys := make([][]byte, n)
	for i := range addrs {
		addrs[i] = addr(i)
		keys[i] = []byte{byte(i)}
	}
	s, err := NewSet(addrs, keys, types.ProposerPolicy{ID: policy})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A-04 §5.3.
func TestProposerWorkedExample(t *testing.T) {
	lasts := []types.Address{{}, addr(1), addr(3), addr(9)}
	want := map[uint64][][]int{
		0: {{0, 1, 2, 3, 0, 1}, {2, 3, 0, 1, 2, 3}, {0, 1, 2, 3, 0, 1}, {1, 2, 3, 0, 1, 2}},
		1: {{0, 1, 2, 3, 0, 1}, {1, 2, 3, 0, 1, 2}, {3, 0, 1, 2, 3, 0}, {0, 1, 2, 3, 0, 1}},
		7: {{0, 1, 2, 3, 0, 1}, {2, 3, 0, 1, 2, 3}, {0, 1, 2, 3, 0, 1}, {1, 2, 3, 0, 1, 2}},
	}
	for pol, rows := range want {
		s := set(t, 4, pol)
		for li, row := range rows {
			for r, w := range row {
				if got := s.CalcProposer(lasts[li], uint64(r)); got != w {
					t.Errorf("policy %d last %d round %d: %d, want %d", pol, li, r, got, w)
				}
			}
		}
	}
	// The seed wraps modulo 2^64.
	if got := set(t, 3, 0).CalcProposer(addr(2), math.MaxUint64); got != 2 {
		t.Errorf("round robin wrap: %d", got)
	}
	if got := set(t, 3, 1).CalcProposer(addr(2), math.MaxUint64); got != 1 {
		t.Errorf("sticky wrap: %d", got)
	}
	if got := set(t, 0, 0).CalcProposer(addr(1), 0); got != -1 {
		t.Errorf("empty set: %d", got)
	}
}

// A-04 §5.4: duplicate addresses and the empty set.
func TestIsProposer(t *testing.T) {
	a, b := addr(1), addr(2)
	s, _ := NewSet([]types.Address{a, b, a}, [][]byte{{1}, {2}, {3}}, types.ProposerPolicy{})
	if s.IsProposer(2, a) {
		t.Error("later entry with another key is the proposer")
	}
	if !s.IsProposer(0, a) || s.IsProposer(0, b) {
		t.Error("first entry")
	}
	same, _ := NewSet([]types.Address{a, b, a}, [][]byte{{1}, {2}, {1}}, types.ProposerPolicy{})
	if !same.IsProposer(2, a) {
		t.Error("later entry with the same key is not the proposer")
	}
	empty, _ := NewSet(nil, nil, types.ProposerPolicy{})
	if !empty.IsProposer(-1, a) || empty.Quorum() != 1 {
		t.Error("empty set")
	}
	if _, err := NewSet([]types.Address{a, b}, [][]byte{{1}}, types.ProposerPolicy{}); !errors.Is(err, ErrKeysShort) {
		t.Error("short key list accepted")
	}
}

func u64(v uint64) *uint64 { return &v }

// A-04 §4.2.
func TestEpochScheduleWorkedExample(t *testing.T) {
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 10, ProposerPolicy: u64(0)}, []types.Transition{
		{Block: big.NewInt(50), WBFT: &types.WBFTParams{EpochLength: 7}},
		{Block: big.NewInt(25), WBFT: &types.WBFTParams{EpochLength: 7}},
		{Block: big.NewInt(40), WBFT: &types.WBFTParams{BlockPeriodSeconds: 2, ProposerPolicy: u64(1)}},
	}, types.GenesisInit{}, nil)
	var epochs []uint64
	for n := uint64(0); n <= 70; n++ {
		if ok, _ := IsEpochBlock(cfg, types.HeightFromUint64(n)); ok {
			epochs = append(epochs, n)
		}
	}
	want := []uint64{0, 10, 20, 25, 32, 39, 46, 50, 57, 64}
	if len(epochs) != len(want) {
		t.Fatalf("epoch blocks %v", epochs)
	}
	for i := range want {
		if epochs[i] != want[i] {
			t.Fatalf("epoch blocks %v", epochs)
		}
	}
	for n, w := range map[uint64]uint64{24: 20, 25: 25, 26: 25, 45: 39, 49: 46, 50: 50, 70: 64} {
		last, err := LastEpochBlock(cfg, types.HeightFromUint64(n))
		if err != nil || last.RefLow64() != w {
			t.Errorf("last_epoch_block(%d) = %s, want %d", n, last, w)
		}
	}
	zero := types.NewConfig(types.WBFTParams{}, nil, types.GenesisInit{}, nil)
	if _, err := IsEpochBlock(zero, types.HeightFromUint64(3)); !errors.Is(err, ErrZeroEpochLength) {
		t.Errorf("zero epoch length: %v", err)
	}
}

// memChain is a types.ChainReader over headers; canonical ones are indexed
// by number.
type memChain struct {
	byHash map[types.Hash]*types.Header
	byNum  map[uint64]*types.Header
}

func newMemChain() *memChain {
	return &memChain{byHash: map[types.Hash]*types.Header{}, byNum: map[uint64]*types.Header{}}
}

func (c *memChain) add(h *types.Header, canonical bool) {
	c.byHash[codec.BlockHash(h)] = h
	if canonical {
		c.byNum[h.Number.RefLow64()] = h
	}
}
func (c *memChain) Head() *types.Header                     { return nil }
func (c *memChain) HeaderByNumber(i uint64) *types.Header   { return c.byNum[i] }
func (c *memChain) HeaderByHash(h types.Hash) *types.Header { return c.byHash[h] }
func (c *memChain) HasBlock(h types.Hash, i uint64) bool    { return c.Header(h, i) != nil }
func (c *memChain) Header(h types.Hash, i uint64) *types.Header {
	x := c.byHash[h]
	if x == nil || x.Number.RefLow64() != i {
		return nil
	}
	return x
}

func mkHeader(t *testing.T, n uint64, parent *types.Header, ei *types.EpochInfo) *types.Header {
	t.Helper()
	h := &types.Header{Number: types.HeightFromUint64(n), Difficulty: big.NewInt(1), Time: n}
	if parent != nil {
		h.ParentHash = codec.BlockHash(parent)
	}
	if err := codec.SetExtra(h, &types.WBFTExtra{EpochInfo: ei, GasTip: big.NewInt(0), Round: uint32(n)}); err != nil {
		t.Fatal(err)
	}
	return h
}

func epochOf(idx ...int) *types.EpochInfo {
	ei := &types.EpochInfo{}
	for i, a := range idx {
		ei.Candidates = append(ei.Candidates, types.Candidate{Addr: addr(a), Diligence: types.DefaultDiligence})
		ei.Validators = append(ei.Validators, uint32(i))
		ei.BLSPublicKeys = append(ei.BLSPublicKeys, []byte{byte(a)})
	}
	return ei
}

func TestValidatorsAt(t *testing.T) {
	cfg := types.NewConfig(types.WBFTParams{EpochLength: 4, ProposerPolicy: u64(0)},
		[]types.Transition{{Block: big.NewInt(6), WBFT: &types.WBFTParams{ProposerPolicy: u64(1)}}},
		types.GenesisInit{Validators: []types.Address{addr(0), addr(1)}, BLSPublicKeys: [][]byte{{0}, {1}}}, nil)
	c := newMemChain()
	g := mkHeader(t, 0, nil, epochOf(0, 1, 2))
	c.add(g, true)
	hs := []*types.Header{g}
	for n := uint64(1); n <= 6; n++ {
		var ei *types.EpochInfo
		if n == 4 {
			ei = epochOf(3, 4)
		}
		h := mkHeader(t, n, hs[n-1], ei)
		c.add(h, true)
		hs = append(hs, h)
	}
	check := func(n uint64, parent *types.Header, want []int, pol uint64) {
		t.Helper()
		vs, err := ValidatorsAt(c, cfg, types.HeightFromUint64(n), codec.BlockHash(parent), nil)
		if err != nil {
			t.Fatalf("validators_at(%d): %v", n, err)
		}
		if vs.Len() != len(want) || vs.Policy().ID != pol {
			t.Fatalf("validators_at(%d): %d members, policy %d", n, vs.Len(), vs.Policy().ID)
		}
		for i, w := range want {
			if vs.At(i).Addr != addr(w) {
				t.Errorf("validators_at(%d)[%d] = %x", n, i, vs.At(i).Addr)
			}
		}
	}
	// Height 0 is the configuration's genesis set.
	vs, err := ValidatorsAt(c, cfg, types.HeightFromUint64(0), types.Hash{}, nil)
	if err != nil || vs.Len() != 2 {
		t.Fatalf("genesis set: %v", err)
	}
	check(1, hs[0], []int{0, 1, 2}, 0)
	check(4, hs[3], []int{0, 1, 2}, 0) // an epoch block is sealed by the previous set
	check(5, hs[4], []int{3, 4}, 0)
	check(6, hs[5], []int{3, 4}, 1)

	// Without the canonical epoch header the lookup walks back.
	walk := newMemChain()
	for i, h := range hs {
		walk.add(h, i != 4)
	}
	if vs, err := ValidatorsAt(walk, cfg, types.HeightFromUint64(6), codec.BlockHash(hs[5]), nil); err != nil || vs.At(0).Addr != addr(3) {
		t.Errorf("walk back: %v", err)
	}
	// ... or finds the header among the pending parents.
	partial := newMemChain()
	for _, h := range hs[:4] {
		partial.add(h, true)
	}
	if _, err := ValidatorsAt(partial, cfg, types.HeightFromUint64(6), codec.BlockHash(hs[5]), nil); !errors.Is(err, ErrUnknownAncestor) {
		t.Errorf("missing ancestor: %v", err)
	}
	if vs, err := ValidatorsAt(partial, cfg, types.HeightFromUint64(6), codec.BlockHash(hs[5]), hs[4:6]); err != nil || vs.At(0).Addr != addr(3) {
		t.Errorf("parents: %v", err)
	}
	// An epoch header without EpochInfo.
	noInfo := newMemChain()
	for i, h := range hs {
		if i == 4 {
			h = mkHeader(t, 4, hs[3], nil)
		}
		noInfo.add(h, true)
	}
	if _, err := ValidatorsAt(noInfo, cfg, types.HeightFromUint64(5), types.Hash{}, nil); !errors.Is(err, ErrEpochInfoNil) {
		t.Errorf("epoch info nil: %v", err)
	}
}
