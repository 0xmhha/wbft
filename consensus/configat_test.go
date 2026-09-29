package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// The core reads the block period for the next block at latest_number + 1
// and the round timeout at the current sequence: with the head at 9, a
// transition at block 10 applies to sequence 10 and one at block 11 does not.
//
// Covers: WBFT-PARAM-053
func TestConfigAtArguments(t *testing.T) {
	pol, maxRT := uint64(0), uint64(60)
	base := types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &pol}
	changed := &types.WBFTParams{RequestTimeoutSeconds: 7, BlockPeriodSeconds: 3, MaxRequestTimeoutSeconds: &maxRT}
	for _, tt := range []struct {
		at      int64
		applies bool
	}{{10, true}, {11, false}} {
		h := newHarness(t, 4, 1)
		cfg := types.NewConfig(base, []types.Transition{{Block: big.NewInt(tt.at), WBFT: changed}}, types.GenesisInit{}, nil)
		h.s = NewState(Options{Config: cfg, Self: h.addrs[1]})
		out := h.start()
		seq := types.HeightFromUint64(10)
		wantPeriod := uint64(1)
		wantTimeout, _ := RoundTimeout(types.NewConfig(base, nil, types.GenesisInit{}, nil).ConfigAt(seq), types.RoundFromUint64(0))
		if tt.applies {
			wantPeriod = 3
			wantTimeout, _ = RoundTimeout(cfg.ConfigAt(seq), types.RoundFromUint64(0))
		}
		builds := outputsOf[RequestBuild](out)
		if len(builds) != 1 || builds[0].BlockPeriod != wantPeriod {
			t.Errorf("transition at %d: build requests %+v, want block period %d", tt.at, builds, wantPeriod)
		}
		var round []ArmTimer
		for _, a := range outputsOf[ArmTimer](out) {
			if a.Kind == RoundTimer {
				round = append(round, a)
			}
		}
		if len(round) != 1 || round[0].Duration != wantTimeout {
			t.Errorf("transition at %d: round timers %+v, want %v", tt.at, round, wantTimeout)
		}
	}
	// The two configurations give different timeouts, so the check above
	// tells the arguments apart.
	a, _ := RoundTimeout(types.NewConfig(base, nil, types.GenesisInit{}, nil).ConfigAt(types.HeightFromUint64(10)), types.RoundFromUint64(0))
	b, _ := RoundTimeout(types.NewConfig(base, []types.Transition{{Block: big.NewInt(10), WBFT: changed}}, types.GenesisInit{}, nil).ConfigAt(types.HeightFromUint64(10)), types.RoundFromUint64(0))
	if a == b || a <= 0 || b <= 0 || a > time.Hour {
		t.Fatalf("timeouts %v and %v do not differ", a, b)
	}
}

// The extra seals for the proposal after head are those stored for (head
// number, prior round) with the head's hash, indexed in the prior validator
// set; seals of a sender outside that set, of another round or of another
// block are dropped.
//
// Covers: WBFT-HDR-035
func TestExtraSealsSelection(t *testing.T) {
	h := newHarness(t, 5, 1)
	head := h.block(10, 0, h.addrs[0])
	other := h.block(10, 1, h.addrs[0])
	// The prior set lists validators 3, 0, 2 in that order; 1 and 4 are
	// outside it.
	prior, err := validator.NewSet([]types.Address{h.addrs[3], h.addrs[0], h.addrs[2]}, [][]byte{{3}, {0}, {2}}, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	hash := codec.BlockHash(head.Header)
	at := types.View{Sequence: types.HeightFromUint64(10), Round: types.RoundFromUint64(2)}
	entry := func(i int, v types.View, d types.Hash) ExtraSealEntry {
		return ExtraSealEntry{Source: h.addrs[i], View: v, Digest: d, Seal: []byte{byte(i)}}
	}
	snap := &Snapshot{
		Running: true, PriorRound: types.RoundFromUint64(2), PriorValidators: prior,
		ExtraPrepare: []ExtraSealEntry{
			entry(0, at, hash), entry(1, at, hash), entry(2, at, hash),
			entry(3, types.View{Sequence: at.Sequence, Round: types.RoundFromUint64(1)}, hash),
		},
		ExtraCommit: []ExtraSealEntry{
			entry(4, at, hash), entry(3, at, hash), entry(0, at, codec.BlockHash(other.Header)),
		},
	}
	prepared, committed := snap.ExtraSeals(head.Header)
	want := func(got []types.SealEntry, want []types.SealEntry) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i].Sealer != want[i].Sealer || string(got[i].Seal) != string(want[i].Seal) {
				return false
			}
		}
		return true
	}
	if !want(prepared, []types.SealEntry{{Sealer: 1, Seal: []byte{0}}, {Sealer: 2, Seal: []byte{2}}}) {
		t.Errorf("prepared %+v", prepared)
	}
	if !want(committed, []types.SealEntry{{Sealer: 0, Seal: []byte{3}}}) {
		t.Errorf("committed %+v", committed)
	}
	stopped := *snap
	stopped.Running = false
	if p, c := stopped.ExtraSeals(head.Header); len(p) != 0 || len(c) != 0 {
		t.Error("seals of a core that is not running")
	}
}
