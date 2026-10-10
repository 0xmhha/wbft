package participation

import (
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// headerChain is a ChainReader over a few headers.
type headerChain struct {
	head   *types.Header
	byHash map[types.Hash]*types.Header
}

func (c headerChain) Head() *types.Header                         { return c.head }
func (c headerChain) HeaderByNumber(uint64) *types.Header         { return nil }
func (c headerChain) Header(h types.Hash, _ uint64) *types.Header { return c.byHash[h] }
func (c headerChain) HeaderByHash(h types.Hash) *types.Header     { return c.byHash[h] }
func (c headerChain) HasBlock(h types.Hash, _ uint64) bool        { return c.byHash[h] != nil }

func seal(idx ...uint32) *types.AggregatedSeal {
	var s types.SealerSet
	for _, i := range idx {
		s.SetSealer(i)
	}
	return &types.AggregatedSeal{Sealers: s}
}

func view(seq, round string) *event.View { return &event.View{Seq: seq, Round: round} }

func at(ms int64) event.Stamp { return event.Stamp{Wall: time.UnixMilli(ms)} }

// TestRecorder records heights 1 to 3 of a four-validator chain: height 1
// decided at round 0 with this node's messages, height 2 at round 1 after
// a timeout, height 3 from its headers alone. The node announces heads 1,
// 2 and 4, so height 3 is recorded with head 4 from the chain.
//
// Covers: WBFT-SEC-130
func TestRecorder(t *testing.T) {
	addrs := []types.Address{{0xa0}, {0xa1}, {0xa2}, {0xa3}}
	vs, err := validator.NewSet(addrs, make([][]byte, 4), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	a := func(i int) string { return hexAddr(addrs[i]) }
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	mk := func(n uint64, parent *types.Header, coinbase types.Address, tm uint64, x *types.WBFTExtra) *types.Header {
		h := &types.Header{Number: types.HeightFromUint64(n), Coinbase: coinbase, Time: tm}
		if parent != nil {
			h.ParentHash = codec.BlockHash(parent)
		}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		return h
	}
	h0 := mk(0, nil, types.Address{}, 100, &types.WBFTExtra{})
	h1 := mk(1, h0, addrs[0], 101, &types.WBFTExtra{PreparedSeal: seal(0, 1, 2), CommittedSeal: seal(0, 1, 2)})
	h2 := mk(2, h1, addrs[2], 103, &types.WBFTExtra{Round: 1, PreparedSeal: seal(1, 2, 3), CommittedSeal: seal(1, 2, 3),
		PrevPreparedSeal: seal(0, 1, 2), PrevCommittedSeal: seal(0, 1, 2, 3)})
	h3 := mk(3, h2, addrs[3], 104, &types.WBFTExtra{PreparedSeal: seal(0, 1, 2), CommittedSeal: seal(0, 1, 2),
		PrevPreparedSeal: seal(1, 2, 3), PrevCommittedSeal: seal(1, 2, 3)})
	h4 := mk(4, h3, addrs[1], 105, &types.WBFTExtra{PrevPreparedSeal: seal(0, 1, 2), PrevCommittedSeal: seal(0, 1, 2)})
	chain.head = h0

	dropped := 0
	r, err := Open(fsys.NewMem(), "/part", Options{Chain: chain, Dropped: func() { dropped++ },
		ValidatorsAt: func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil },
		Period:       func(types.Height) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	msg := func(seq, round string, code uint64, src, via string, ms int64, check string) {
		f := map[string]any{"code": code, "source": src, "via": via, "peer": a(2), "dedup_key": "0x01", "outcome": event.Accept, "check": check}
		r.Consume(event.Record{Kind: event.MsgOutcome, View: view(seq, round), Fields: f}, at(ms))
	}
	enter := func(seq, round, branch, cause string, ms int64) {
		r.Consume(event.Record{Kind: event.RoundEnter, View: view(seq, round), Fields: map[string]any{"branch": branch, "cause": cause}}, at(ms))
	}
	// Height 1, round 0 starts at 100 s + 1 s.
	enter("1", "0", "INITIAL", event.CauseStart, 100_900)
	msg("1", "0", 0x12, a(1), "direct", 101_100, "")
	msg("1", "0", 0x13, a(0), "self", 101_200, "")
	msg("1", "0", 0x13, a(2), "direct", 101_300, "")
	msg("1", "0", 0x13, a(2), "backlog", 101_400, "")         // not the first
	msg("1", "0", 0x13, a(3), "direct", 101_300, "prefilter") // not an arrival
	msg("1", "0", 0x14, hexAddr(types.Address{0xee}), "direct", 101_300, "")
	// Height 2: round 0 times out, round 1 decides; evidence of a2.
	enter("2", "0", "INITIAL", event.CauseNewHead, 102_000)
	enter("2", "1", "ROUND_CHANGE", event.CauseTimeout, 104_000)
	msg("2", "1", 0x15, a(3), "direct", 104_250, "")
	r.Consume(event.Record{Kind: event.Evidence, View: view("2", "1"), Fields: map[string]any{"source": a(2)}}, at(104_300))
	r.Head(h1)
	r.Head(h2)
	r.Head(h4)
	r.Head(h2) // an earlier head changes nothing
	r.Close()
	if dropped != 0 {
		t.Fatalf("%d dropped", dropped)
	}

	got, err := r.Range(big.NewInt(1), big.NewInt(4))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Height != "1" || got[3].Height != "4" || !got[3].Gap || got[2].Gap {
		t.Fatalf("range: %+v", got)
	}
	row := func(rec Record, round string, i int) ValidatorRound {
		t.Helper()
		for _, v := range rec.Validators {
			if v.Round == round && v.Validator == a(i) {
				return v
			}
		}
		t.Fatalf("height %s: no row %s/%d in %+v", rec.Height, round, i, rec.Validators)
		return ValidatorRound{}
	}

	r1 := got[0]
	if r1.Source != "local" || r1.Round != "0" || r1.Proposer != a(0) || len(r1.Rounds) != 1 || len(r1.Validators) != 4 {
		t.Fatalf("height 1: %+v", r1)
	}
	if rd := r1.Rounds[0]; rd.Outcome != "committed" || rd.Proposer != a(0) || rd.Cause != "" || rd.Start == nil || !rd.Start.Equal(time.Unix(101, 0)) {
		t.Fatalf("height 1 round 0: %+v", rd)
	}
	if v := row(r1, "0", 1); v.IsProposer || v.Preprepare == nil || *v.Preprepare.DelayMs != 100 || !v.SealedPrepared || !v.InPrevCommitted || v.Extra {
		t.Fatalf("height 1, a1: %+v", v)
	}
	if v := row(r1, "0", 0); v.Prepare == nil || v.Prepare.Via != "self" || !v.IsProposer {
		t.Fatalf("height 1, a0: %+v", v)
	}
	if v := row(r1, "0", 2); v.Prepare == nil || v.Prepare.Via != "direct" || *v.Prepare.DelayMs != 300 || v.Prepare.Outcome != "ACCEPT" {
		t.Fatalf("height 1, a2: %+v", v)
	}
	// a3 sealed late: in height 2's prev committed seal only.
	if v := row(r1, "0", 3); v.Prepare != nil || v.SealedCommitted || v.InPrevPrepared || !v.InPrevCommitted || !v.Extra {
		t.Fatalf("height 1, a3: %+v", v)
	}

	r2 := got[1]
	if r2.Source != "local" || r2.Round != "1" || len(r2.Rounds) != 2 {
		t.Fatalf("height 2: %+v", r2)
	}
	// After proposer a0: a1 in round 0, a2 in round 1.
	if rd := r2.Rounds[0]; rd.Outcome != "round_change" || rd.Proposer != a(1) || rd.Entered == nil {
		t.Fatalf("height 2 round 0: %+v", rd)
	}
	if rd := r2.Rounds[1]; rd.Outcome != "committed" || rd.Proposer != a(2) || rd.Cause != "timeout" || !rd.Start.Equal(time.UnixMilli(104_000)) {
		t.Fatalf("height 2 round 1: %+v", rd)
	}
	if v := row(r2, "1", 3); v.IsProposer || v.RoundChange == nil || *v.RoundChange.DelayMs != 250 {
		t.Fatalf("height 2, a3: %+v", v)
	}
	if v := row(r2, "1", 2); !v.Evidence || !v.SealedCommitted || !v.IsProposer {
		t.Fatalf("height 2, a2: %+v", v)
	}
	if len(r2.Validators) != 4 {
		t.Fatalf("height 2 rows: %+v", r2.Validators)
	}

	r3 := got[2]
	if r3.Source != "header" || r3.Round != "0" || len(r3.Validators) != 4 || r3.Rounds[0].Entered != nil {
		t.Fatalf("height 3: %+v", r3)
	}
	if v := row(r3, "0", 3); v.SealedPrepared || v.InPrevPrepared {
		t.Fatalf("height 3, a3: %+v", v)
	}
}

// TestStore checks the gap records, a torn last line, a height written
// twice and the removal of whole files below the floor.
func TestStore(t *testing.T) {
	f := fsys.NewMem()
	s, err := openStore(f, "/p")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []int64{1, 300, 600, 600} {
		if err := s.put(big.NewInt(h), &Record{Height: big.NewInt(h).String(), Source: "header", Time: uint64(h)}); err != nil { //nolint:gosec // small
			t.Fatal(err)
		}
	}
	if err := s.put(big.NewInt(601), &Record{Height: "601", Source: "local"}); err != nil {
		t.Fatal(err)
	}
	w, err := f.OpenFile(path.Join("/p", "p-2.jsonl"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{"height":"602"`))
	_ = w.Close()
	got, err := s.rangeOf(big.NewInt(600), big.NewInt(602))
	if err != nil || len(got) != 3 || got[0].Source != "header" || got[1].Source != "local" || !got[2].Gap {
		t.Fatalf("600..602: %+v %v", got, err)
	}
	// The floor 512 removes buckets 0 (0..255) and 1 (256..511).
	if err := s.prune(big.NewInt(512)); err != nil {
		t.Fatal(err)
	}
	if bs, _ := s.buckets(); len(bs) != 1 || bs[0].Int64() != 2 {
		t.Fatalf("buckets after pruning: %v", bs)
	}
	got, err = s.rangeOf(big.NewInt(1), big.NewInt(1))
	if err != nil || len(got) != 1 || !got[0].Gap {
		t.Fatalf("height 1 after pruning: %+v %v", got, err)
	}
}
