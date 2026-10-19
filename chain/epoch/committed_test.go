package epoch

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// hashEpochChain has no canonical-number index. Historical scoring must stay
// on the selected hash ancestry, including heights outside the uint64 domain.
type hashEpochChain map[types.Hash]*types.Header

func (c hashEpochChain) Head() *types.Header                     { return nil }
func (c hashEpochChain) HeaderByHash(h types.Hash) *types.Header { return c[h] }
func (c hashEpochChain) Header(types.Hash, uint64) *types.Header { panic("number lookup") }
func (c hashEpochChain) HeaderByNumber(uint64) *types.Header     { panic("canonical lookup") }
func (c hashEpochChain) HasBlock(types.Hash, uint64) bool        { panic("number lookup") }

func committedTestConfig(t *testing.T, activation string) *types.Config {
	t.Helper()
	cfg, err := types.ParseChainConfig([]byte(`{"anzeon":{"wbft":{"epochLength":2,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"committedEpochDiligence":` + activation + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestCommittedEpochFullHeightAndRound(t *testing.T) {
	start := new(big.Int).Lsh(big.NewInt(1), 64)
	height := func(i int64) types.Height { return types.MustHeightFromBig(new(big.Int).Add(start, big.NewInt(i))) }
	entries := []types.CandidateEntry{{Addr: types.Address{1}, BLSPublicKey: []byte{1}}, {Addr: types.Address{2}, BLSPublicKey: []byte{2}}}
	ei := &types.EpochInfo{Candidates: []types.Candidate{{Addr: entries[0].Addr, Diligence: types.DefaultDiligence}, {Addr: entries[1].Addr, Diligence: types.DefaultDiligence}}, Validators: []uint32{0, 1}, BLSPublicKeys: [][]byte{{1}, {2}}}
	c := hashEpochChain{}
	var parent *types.Header
	for i := int64(0); i < 4; i++ {
		h := &types.Header{Number: height(i), Difficulty: big.NewInt(1), Coinbase: entries[i%2].Addr}
		if parent != nil {
			h.ParentHash = codec.BlockHash(parent)
		}
		x := &types.WBFTExtra{GasTip: big.NewInt(0), PrevPreparedSeal: bitmap(0, 1), PrevCommittedSeal: bitmap(0, 1)}
		if i%2 == 0 {
			x.EpochInfo = ei
		}
		if i == 3 {
			x.Round = math.MaxUint32
		}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		c[codec.BlockHash(h)] = h
		parent = h
	}
	e := &types.Header{Number: height(4), ParentHash: codec.BlockHash(parent), Difficulty: big.NewInt(1)}
	if err := codec.SetExtra(e, &types.WBFTExtra{GasTip: big.NewInt(0), PrevRound: math.MaxUint32}); err != nil {
		t.Fatal(err)
	}
	cfg := committedTestConfig(t, height(4).String())
	got, err := ComputeNextEpochInfo(c, cfg, e, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range got.Candidates {
		if candidate.Diligence != 1_810_000 {
			t.Fatal("full round opportunities or normalization changed", candidate.Diligence)
		}
	}
	// The current header is outside the observed window, including its Round.
	if err = codec.SetExtra(e, &types.WBFTExtra{GasTip: big.NewInt(0), Round: math.MaxUint32, PrevRound: math.MaxUint32}); err != nil {
		t.Fatal(err)
	}
	again, err := ComputeNextEpochInfo(c, cfg, e, entries)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("current round changes score", err)
	}
	alias := e.Copy()
	alias.Number = types.HeightFromUint64(4)
	if _, err = ComputeNextEpochInfo(c, cfg, alias, entries); !errors.Is(err, validator.ErrUnknownAncestor) {
		t.Fatal("activation did not bind the full actual parent", err)
	}
	// Only the successor's bound previous round determines observations.
	localCopy := parent.Copy()
	localExtra, err := codec.DecodeExtra(localCopy)
	if err != nil {
		t.Fatal(err)
	}
	localExtra.Round = 0
	if err = codec.SetExtra(localCopy, localExtra); err != nil {
		t.Fatal(err)
	}
	if codec.BlockHash(localCopy) != e.ParentHash {
		t.Fatal("local copy changed block hash")
	}
	c[e.ParentHash] = localCopy
	localResult, err := ComputeNextEpochInfo(c, cfg, e, entries)
	if err != nil || !reflect.DeepEqual(got, localResult) {
		t.Fatal("node-local round affected hash-bound score", err)
	}
	c[e.ParentHash] = parent
	// Classification must not bypass an active hash-bound rule.
	nonEpochAlias := e.Copy()
	nonEpochAlias.Number = height(3)
	if _, err = ComputeNextEpochInfo(c, cfg, nonEpochAlias, entries); !errors.Is(err, validator.ErrUnknownAncestor) {
		t.Fatal("non-epoch alias bypassed actual-parent activation", err)
	}
	zeroAlias := e.Copy()
	zeroAlias.Number = types.Height{}
	if _, err = ComputeNextEpochInfo(c, cfg, zeroAlias, entries); !errors.Is(err, validator.ErrUnknownAncestor) {
		t.Fatal("genesis alias bypassed actual-parent activation", err)
	}
	// A lookup returning different contents under the requested hash is invalid.
	c[e.ParentHash] = parent.Copy()
	c[e.ParentHash].Coinbase = types.Address{9}
	if _, err = ComputeNextEpochInfo(c, cfg, e, entries); !errors.Is(err, validator.ErrUnknownAncestor) {
		t.Fatal("unbound parent contents", err)
	}
}

func TestCommittedDiligenceObservationWeights(t *testing.T) {
	D := types.DiligenceDenominator
	for _, prior := range []uint64{0, D, types.DefaultDiligence, 2 * D} {
		for slots := int64(0); slots <= 4; slots++ {
			for submitted := int64(0); submitted <= 2*slots; submitted++ {
				for credit := int64(0); credit <= 8; credit++ {
					o := &committedObservation{}
					o.slots.SetInt64(slots)
					o.submitted.SetInt64(submitted)
					o.capacity.SetInt64(8)
					o.credit.SetInt64(credit)
					got, err := committedDiligence(prior, o, big.NewInt(4))
					if err != nil || got > 2*D {
						t.Fatal("bounded observations", got, err)
					}
					if slots == 0 && got != prior {
						t.Fatal("zero observations changed prior")
					}
				}
			}
		}
	}
	// Large products retain full precision; the mathematically exact result is D/5.
	huge := new(big.Int).Lsh(big.NewInt(1), 130)
	o := &committedObservation{}
	o.slots.Set(huge)
	o.submitted.Mul(huge, big.NewInt(2))
	o.capacity.Set(huge)
	o.credit.Set(huge)
	got, err := committedDiligence(0, o, huge)
	if err != nil || got != D/5 {
		t.Fatal("large exact arithmetic", got, err)
	}
	before, _ := json.Marshal([]string{o.slots.String(), o.submitted.String(), o.capacity.String(), o.credit.String(), huge.String()})
	_, err = committedDiligence(0, o, huge)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal([]string{o.slots.String(), o.submitted.String(), o.capacity.String(), o.credit.String(), huge.String()})
	if string(before) != string(after) {
		t.Fatal("input arithmetic was mutated")
	}
	invalid := []*committedObservation{{}, {}, {}, {}}
	invalid[0].slots.SetInt64(5)
	invalid[1].slots.SetInt64(1)
	invalid[1].submitted.SetInt64(3)
	invalid[2].credit.SetInt64(1)
	invalid[3].slots.SetInt64(-1)
	for _, o := range invalid {
		if _, err := committedDiligence(D, o, big.NewInt(4)); !errors.Is(err, ErrSealCountRange) {
			t.Fatal("invalid observation accepted", err)
		}
	}
}

func TestCommittedEpochHistoricalPolicyAndPartialWindow(t *testing.T) {
	cfg, err := types.ParseChainConfig([]byte(`{"anzeon":{"wbft":{"epochLength":4,"proposerPolicy":0}},"transitions":[{"block":5,"proposerPolicy":1},{"block":6,"epochLength":8}],"wbftRules":{"consensusRules":{"committedEpochDiligence":6}}}`))
	if err != nil {
		t.Fatal(err)
	}
	entries := []types.CandidateEntry{{Addr: types.Address{1}, BLSPublicKey: []byte{1}}, {Addr: types.Address{2}, BLSPublicKey: []byte{2}}}
	ei := &types.EpochInfo{Candidates: []types.Candidate{{Addr: entries[0].Addr, Diligence: types.DefaultDiligence}, {Addr: entries[1].Addr, Diligence: types.DefaultDiligence}}, Validators: []uint32{0, 1}, BLSPublicKeys: [][]byte{{1}, {2}}}
	c := hashEpochChain{}
	var parent *types.Header
	for i := uint64(0); i < 6; i++ {
		h := &types.Header{Number: types.HeightFromUint64(i), Difficulty: big.NewInt(1), Coinbase: entries[i%2].Addr}
		if parent != nil {
			h.ParentHash = codec.BlockHash(parent)
		}
		x := &types.WBFTExtra{GasTip: big.NewInt(0), PrevPreparedSeal: bitmap(0, 1), PrevCommittedSeal: bitmap(0, 1)}
		if i == 0 || i == 4 {
			x.EpochInfo = ei
		}
		if i == 5 {
			x.Round = 1
		}
		if err = codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		c[codec.BlockHash(h)] = h
		parent = h
	}
	e := &types.Header{Number: types.HeightFromUint64(6), ParentHash: codec.BlockHash(parent), Difficulty: big.NewInt(1)}
	if err = codec.SetExtra(e, &types.WBFTExtra{GasTip: big.NewInt(0), PrevRound: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := ComputeNextEpochInfo(c, cfg, e, entries)
	if err != nil || got == nil {
		t.Fatal("partial-window fixture must resolve an epoch", err)
	}
	for i, want := range []uint64{1_860_000, 1_910_000} {
		if got.Candidates[i].Diligence != want {
			t.Fatal("historical policy or actual window span", i, got.Candidates[i].Diligence, want)
		}
	}
}
