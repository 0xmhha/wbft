package node

import (
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/types"
)

// headerChain is a ChainReader over a few headers.
type headerChain struct{ byHash map[types.Hash]*types.Header }

func (c headerChain) Head() *types.Header                 { return nil }
func (c headerChain) HeaderByNumber(uint64) *types.Header { return nil }
func (c headerChain) Header(h types.Hash, _ uint64) *types.Header {
	return c.byHash[h]
}
func (c headerChain) HeaderByHash(h types.Hash) *types.Header { return c.byHash[h] }
func (c headerChain) HasBlock(h types.Hash, _ uint64) bool    { return c.byHash[h] != nil }

func seal(idx ...uint32) *types.AggregatedSeal {
	var s types.SealerSet
	for _, i := range idx {
		s.SetSealer(i)
	}
	return &types.AggregatedSeal{Sealers: s}
}

// TestValidatorMetrics derives the per-validator series from two headers of
// a four-validator set: block 1 decided at round 0 with three sealers, and
// block 2 decided at round 2 whose prev seals carry block 1's sealers plus
// a late one (validator 3, an extra seal).
func TestValidatorMetrics(t *testing.T) {
	addrs := []types.Address{{0xa0}, {0xa1}, {0xa2}, {0xa3}}
	vs, err := validator.NewSet(addrs, make([][]byte, 4), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	mk := func(n uint64, parent types.Hash, coinbase types.Address, x *types.WBFTExtra) *types.Header {
		h := &types.Header{Number: types.HeightFromUint64(n), ParentHash: parent, Coinbase: coinbase}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		return h
	}
	h0 := mk(0, types.Hash{}, types.Address{}, &types.WBFTExtra{})
	h1 := mk(1, codec.BlockHash(h0), addrs[1], &types.WBFTExtra{PreparedSeal: seal(0, 1, 2), CommittedSeal: seal(0, 1, 2)})
	h2 := mk(2, codec.BlockHash(h1), addrs[0], &types.WBFTExtra{Round: 2, PreparedSeal: seal(0, 1, 3), CommittedSeal: seal(1, 2, 3),
		PrevPreparedSeal: seal(0, 1, 2), PrevCommittedSeal: seal(0, 1, 2, 3)})

	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(chain, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil }, nil, nil)
	m.head(h1)
	m.head(h2)
	m.head(h2) // a repeated head is not counted again
	m.head(h1) // nor an earlier one

	got := map[string]float64{}
	for _, f := range reg.Gather() {
		for _, s := range f.Samples {
			got[f.Name+"/"+s.Labels["validator"]+"/"+s.Labels["type"]] = s.Value
		}
	}
	a := func(i int) string { return "0x" + hex.EncodeToString(addrs[i][:]) }
	want := map[string]float64{
		"wbft_validator_seals_total/total/prepared":         6,
		"wbft_validator_seals_total/total/committed":        6,
		"wbft_validator_seals_total/total/prev_prepared":    3,
		"wbft_validator_seals_total/total/prev_committed":   4,
		"wbft_validator_seals_total/total/extra":            1,
		"wbft_validator_seals_total/" + a(3) + "/extra":     1,
		"wbft_validator_seals_total/" + a(3) + "/prepared":  1,
		"wbft_validator_seals_total/" + a(0) + "/committed": 1,
		// Block 2's rounds 0 and 1 after proposer a1: a2 and a3.
		"wbft_validator_missed_proposals_total/total/":        2,
		"wbft_validator_missed_proposals_total/" + a(2) + "/": 1,
		"wbft_validator_missed_proposals_total/" + a(3) + "/": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if got["wbft_validator_missed_proposals_total/"+a(1)+"/"] != 0 || got["wbft_validator_seals_total/"+a(2)+"/extra"] != 0 {
		t.Errorf("unexpected series: %v", got)
	}
}

// TestValidatorMetricsLabelLimit records only "total" for a set above the
// label limit, and no message delay at all.
func TestValidatorMetricsLabelLimit(t *testing.T) {
	addrs := make([]types.Address, validatorLabelLimit+1)
	for i := range addrs {
		addrs[i] = types.Address{byte(i), 1}
	}
	vs, err := validator.NewSet(addrs, make([][]byte, len(addrs)), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	h := &types.Header{Number: types.HeightFromUint64(1)}
	if err := codec.SetExtra(h, &types.WBFTExtra{CommittedSeal: seal(0, 1)}); err != nil {
		t.Fatal(err)
	}
	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(headerChain{}, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil }, nil, nil)
	m.head(h)
	// The delay histogram is off above the limit, "total" included.
	m.observe(event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "2", Round: "1"}}, event.Stamp{Wall: time.Unix(10, 0)})
	m.observe(event.Record{Kind: event.MsgOutcome, View: &event.View{Seq: "2", Round: "1"},
		Fields: map[string]any{"code": uint64(0x13), "source": "0x01"}}, event.Stamp{Wall: time.Unix(11, 0)})
	for _, f := range reg.Gather() {
		if f.Name == "wbft_validator_message_delay_seconds" && len(f.Samples) != 0 {
			t.Fatalf("delays above the limit: %+v", f.Samples)
		}
		for _, s := range f.Samples {
			if s.Labels["validator"] != "total" {
				t.Fatalf("a series of %s above the limit", s.Labels["validator"])
			}
			if f.Name == "wbft_validator_seals_total" && s.Value != 2 {
				t.Fatalf("total %v", s.Value)
			}
		}
	}
}

// fixedHead is a headerChain whose head is h.
type fixedHead struct {
	headerChain
	h *types.Header
}

func (c fixedHead) Head() *types.Header { return c.h }

// TestValidatorMessageDelay measures a source's first message of a code in
// a view from the round's start: the parent's time plus the block period
// for round 0, the node's ROUND_ENTER for a later round. Repeats, messages
// the prefilter dropped and messages of another view are not recorded.
func TestValidatorMessageDelay(t *testing.T) {
	addrs := []types.Address{{0xa0}, {0xa1}, {0xa2}, {0xa3}}
	vs, err := validator.NewSet(addrs, make([][]byte, 4), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	parent := &types.Header{Number: types.HeightFromUint64(5), Time: 1000}
	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(fixedHead{h: parent}, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil },
		func(types.Height) time.Duration { return 2 * time.Second }, nil)
	at := func(d time.Duration) event.Stamp { return event.Stamp{Wall: time.Unix(1000, 0).Add(d)} }
	enter := func(round string, d time.Duration) {
		m.observe(event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "6", Round: round}}, at(d))
	}
	msg := func(seq, round string, code uint64, src int, check string, d time.Duration) {
		f := map[string]any{"code": code, "source": "0x" + hex.EncodeToString(addrs[src][:])}
		if check != "" {
			f["check"] = check
		}
		m.observe(event.Record{Kind: event.MsgOutcome, View: &event.View{Seq: seq, Round: round}, Fields: f}, at(d))
	}
	enter("0", time.Second)                            // the start is 1000+2s, not this
	msg("6", "0", 0x13, 1, "", 2300*time.Millisecond)  // 0.3 s
	msg("6", "0", 0x13, 1, "", 3*time.Second)          // a repeat
	msg("6", "0", 0x13, 2, "prefilter", 3*time.Second) // dropped before the core
	msg("7", "0", 0x13, 2, "", 3*time.Second)          // ahead of the view
	msg("6", "1", 0x13, 2, "", 3*time.Second)          // round 1 not entered yet
	enter("1", 10*time.Second)
	msg("6", "1", 0x14, 3, "", 14*time.Second) // 4 s
	// Block 6 becomes the head at time 1020: round 0 of 7 starts at 1022.
	h6 := &types.Header{Number: types.HeightFromUint64(6), Time: 1020}
	if err := codec.SetExtra(h6, &types.WBFTExtra{}); err != nil {
		t.Fatal(err)
	}
	m.head(h6)
	m.observe(event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "7", Round: "0"}}, at(21*time.Second))
	msg("7", "0", 0x12, 0, "", 22500*time.Millisecond) // 0.5 s

	type obs struct {
		n   uint64
		sum float64
	}
	got := map[string]obs{}
	for _, f := range reg.Gather() {
		if f.Name != "wbft_validator_message_delay_seconds" {
			continue
		}
		for _, s := range f.Samples {
			got[s.Labels["validator"]+"/"+s.Labels["code"]] = obs{s.Count, s.Sum}
		}
	}
	a := func(i int) string { return "0x" + hex.EncodeToString(addrs[i][:]) }
	want := map[string]obs{"total/0x13": {1, 0.3}, a(1) + "/0x13": {1, 0.3}, "total/0x14": {1, 4}, a(3) + "/0x14": {1, 4},
		"total/0x12": {1, 0.5}, a(0) + "/0x12": {1, 0.5}}
	if len(got) != len(want) {
		t.Fatalf("series %v", got)
	}
	for k, w := range want {
		if g := got[k]; g.n != w.n || math.Abs(g.sum-w.sum) > 1e-9 {
			t.Errorf("%s = %+v, want %+v", k, g, w)
		}
	}
}

// TestValidatorMetricsBatchedHeads counts the blocks an application stored
// in a batch and did not announce (the downloader announces the last
// one): after head 1, head 4 counts blocks 2, 3 and 4. A node that
// starts on block 1 counts blocks 2 to 4 at its first head 4; one that
// starts with no head counts only the head.
func TestValidatorMetricsBatchedHeads(t *testing.T) {
	addrs := []types.Address{{0xa0}, {0xa1}}
	vs, err := validator.NewSet(addrs, make([][]byte, 2), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	var hs []*types.Header
	parent := types.Hash{}
	for n := uint64(0); n <= 4; n++ {
		h := &types.Header{Number: types.HeightFromUint64(n), ParentHash: parent}
		if err := codec.SetExtra(h, &types.WBFTExtra{CommittedSeal: seal(0)}); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		hs, parent = append(hs, h), codec.BlockHash(h)
	}
	committed := func(reg *metrics.Registry) float64 {
		for _, f := range reg.Gather() {
			for _, s := range f.Samples {
				if f.Name == "wbft_validator_seals_total" && s.Labels["validator"] == "total" && s.Labels["type"] == "committed" {
					return s.Value
				}
			}
		}
		return 0
	}
	valsAt := func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil }

	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(chain, valsAt, nil, nil)
	m.head(hs[1])
	m.head(hs[4])
	m.head(hs[4]) // announced again: counted once
	if got := committed(reg); got != 4 {
		t.Fatalf("committed seals after heads 1 and 4: %v, want 4", got)
	}

	reg = metrics.NewRegistry()
	m = newValidatorMetrics(reg)
	m.attach(fixedHead{headerChain: chain, h: hs[1]}, valsAt, nil, nil)
	m.head(hs[1]) // the start head itself is not counted
	m.head(hs[4])
	if got := committed(reg); got != 3 {
		t.Fatalf("committed seals after starting on block 1: %v, want 3", got)
	}

	reg = metrics.NewRegistry()
	m = newValidatorMetrics(reg)
	m.attach(chain, valsAt, nil, nil)
	m.head(hs[4])
	if got := committed(reg); got != 1 {
		t.Fatalf("committed seals of the first head without a start head: %v, want 1", got)
	}
}

// TestValidatorMetricsBackfillLimit counts at most backfillMax blocks
// before an announced head, which itself is counted too.
func TestValidatorMetricsBackfillLimit(t *testing.T) {
	vs, err := validator.NewSet([]types.Address{{0xa0}}, make([][]byte, 1), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	var hs []*types.Header
	parent := types.Hash{}
	for n := uint64(0); n <= backfillMax+10; n++ {
		h := &types.Header{Number: types.HeightFromUint64(n), ParentHash: parent}
		if err := codec.SetExtra(h, &types.WBFTExtra{CommittedSeal: seal(0)}); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		hs, parent = append(hs, h), codec.BlockHash(h)
	}
	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(fixedHead{headerChain: chain, h: hs[0]}, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil }, nil, nil)
	m.head(hs[len(hs)-1])
	for _, f := range reg.Gather() {
		for _, s := range f.Samples {
			if f.Name == "wbft_validator_seals_total" && s.Labels["validator"] == "total" && s.Labels["type"] == "committed" &&
				s.Value != backfillMax+1 {
				t.Fatalf("committed seals %v, want %d", s.Value, backfillMax+1)
			}
		}
	}
}

// TestValidatorSeriesPruned removes a validator's series once it has been
// absent from the sets for more than two epochs (observe.md 5.2): a1
// leaves after block 2 and, with epochs of 2 blocks, loses its series at
// block 7. A message source never in a set is removed the same way from
// the head it was first seen at; "total" and a0 stay.
func TestValidatorSeriesPruned(t *testing.T) {
	a0, a1, stranger := types.Address{0xa0}, types.Address{0xa1}, types.Address{0xee}
	both, err := validator.NewSet([]types.Address{a0, a1}, make([][]byte, 2), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	one, err := validator.NewSet([]types.Address{a0}, make([][]byte, 1), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	var hs []*types.Header
	parent := types.Hash{}
	for n := uint64(0); n <= 8; n++ {
		x := &types.WBFTExtra{CommittedSeal: seal(0)}
		if n <= 2 {
			x.CommittedSeal = seal(0, 1)
		}
		if n == 2 { // rounds 0 and 1 missed: a0 and a1
			x.Round = 2
		}
		h := &types.Header{Number: types.HeightFromUint64(n), ParentHash: parent}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		hs, parent = append(hs, h), codec.BlockHash(h)
	}
	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(fixedHead{headerChain: chain, h: hs[0]}, func(n types.Height, _ types.Hash) (*validator.Set, error) {
		if n.RefLow64() <= 2 {
			return both, nil
		}
		return one, nil
	}, func(types.Height) time.Duration { return 0 }, func(types.Height) uint64 { return 2 })
	labels := func() map[string]bool {
		out := map[string]bool{}
		for _, f := range reg.Gather() {
			for _, s := range f.Samples {
				out[s.Labels["validator"]] = true
			}
		}
		return out
	}
	hexOf := func(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }
	for n := 1; n <= 3; n++ {
		m.head(hs[n])
	}
	m.observe(event.Record{Kind: event.RoundEnter, View: &event.View{Seq: "4", Round: "1"}}, event.Stamp{Wall: time.Unix(1, 0)})
	m.observe(event.Record{Kind: event.MsgOutcome, View: &event.View{Seq: "4", Round: "1"},
		Fields: map[string]any{"code": uint64(0x13), "source": hexOf(stranger)}}, event.Stamp{Wall: time.Unix(2, 0)})
	for n := 4; n <= 6; n++ {
		m.head(hs[n])
	}
	if l := labels(); !l[hexOf(a1)] || !l[hexOf(stranger)] {
		t.Fatalf("pruned too early at block 6: %v", l)
	}
	missedA1 := func() bool {
		for _, f := range reg.Gather() {
			for _, s := range f.Samples {
				if f.Name == "wbft_validator_missed_proposals_total" && s.Labels["validator"] == hexOf(a1) {
					return true
				}
			}
		}
		return false
	}
	if !missedA1() {
		t.Fatal("no missed proposal of a1 before pruning")
	}
	m.head(hs[7])
	if l := labels(); l[hexOf(a1)] || !l[hexOf(stranger)] || !l[hexOf(a0)] || !l["total"] {
		t.Fatalf("at block 7: %v", l)
	}
	m.head(hs[8])
	if l := labels(); l[hexOf(stranger)] || !l[hexOf(a0)] {
		t.Fatalf("at block 8: %v", l)
	}
}
