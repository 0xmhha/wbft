package consensus

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// classify is an independent statement of check_message: the rules of
// A-05 section 5.2 written with integer views.
func classify(cs, cr uint64, st StateName, prior uint64, code codec.Code, ms, mr uint64) Class {
	switch {
	case ms > cs+1, ms > cs && mr >= 10, ms == cs && mr > cr+10:
		return TooFar
	}
	less := ms < cs || ms == cs && mr < cr
	greater := ms > cs || ms == cs && mr > cr
	if code == codec.CodeRoundChange {
		switch {
		case ms > cs:
			return Future
		case less:
			return Old
		}
		return Process
	}
	if greater {
		return Future
	}
	if less {
		if cs-ms == 1 && mr == prior && st == AcceptRequest {
			return ExtraSeal
		}
		return Old
	}
	table := map[StateName]map[codec.Code]Class{
		AcceptRequest: {codec.CodePreprepare: Process, codec.CodePrepare: Future, codec.CodeCommit: Future},
		Preprepared:   {codec.CodePreprepare: Invalid, codec.CodePrepare: Process, codec.CodeCommit: Future},
		Prepared:      {codec.CodePreprepare: Invalid, codec.CodePrepare: ExtraSeal, codec.CodeCommit: Process},
		Committed:     {codec.CodePreprepare: Invalid, codec.CodePrepare: ExtraSeal, codec.CodeCommit: ExtraSeal},
	}
	return table[st][code]
}

// Every state, code and view relation around the current view.
func TestCheckMessageTable(t *testing.T) {
	codes := []codec.Code{codec.CodePreprepare, codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange}
	n := 0
	for _, st := range []StateName{AcceptRequest, Preprepared, Prepared, Committed} {
		for _, cr := range []uint64{0, 1, 2, 9} {
			for _, prior := range []uint64{0, 1, 2} {
				for _, code := range codes {
					for ms := uint64(8); ms <= 13; ms++ {
						for mr := uint64(0); mr <= 22; mr++ {
							got := CheckMessage(view(10, cr), st, types.RoundFromUint64(prior), code, view(ms, mr))
							want := classify(10, cr, st, prior, code, ms, mr)
							if got != want {
								t.Fatalf("state %s view (10,%d) prior %d code %d msg (%d,%d): %s, want %s", st, cr, prior, code, ms, mr, got, want)
							}
							n++
						}
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no case")
	}
}

func TestClassAndStateSpellings(t *testing.T) {
	for _, s := range []string{"PROCESS", "FUTURE", "OLD", "INVALID", "TOO_FAR", "EXTRA_SEAL"} {
		c, ok := ParseClass(s)
		if !ok || c.String() != s {
			t.Errorf("class %s", s)
		}
	}
	for _, s := range []string{"AcceptRequest", "Preprepared", "Prepared", "Committed"} {
		st, ok := ParseStateName(s)
		if !ok || st.String() != s {
			t.Errorf("state %s", s)
		}
	}
}

func rc(src byte, seq, round uint64, pr *types.Round, digest types.Hash) RoundChangeSummary {
	return RoundChangeSummary{Source: types.Address{src}, View: view(seq, round), PreparedRound: pr, PreparedDigest: digest}
}

func pp(src byte, seq, round uint64, digest types.Hash) PrepareSummary {
	return PrepareSummary{Source: types.Address{src}, View: view(seq, round), Digest: digest}
}

func TestIsJustifiedProperties(t *testing.T) {
	b := types.Hash{0xb}
	other := types.Hash{0xc}
	target := view(10, 1)
	nilRCs := []RoundChangeSummary{rc(1, 10, 1, nil, types.Hash{}), rc(2, 10, 1, nil, types.Hash{}), rc(3, 10, 1, nil, types.Hash{})}
	if !IsJustified(b, target, nilRCs, nil, 3) {
		t.Fatal("quorum of unprepared ROUND-CHANGEs")
	}
	// Below the quorum.
	if IsJustified(b, target, nilRCs[:2], nil, 3) {
		t.Fatal("below the quorum")
	}
	// Deduplication changes the result: a repeated source counts once.
	dup := []RoundChangeSummary{nilRCs[0], nilRCs[1], rc(1, 10, 1, nil, types.Hash{})}
	if IsJustified(b, target, dup, nil, 3) {
		t.Fatal("a repeated source counted twice")
	}
	// A ROUND-CHANGE of another view.
	for _, stale := range []RoundChangeSummary{rc(3, 10, 2, nil, types.Hash{}), rc(3, 9, 1, nil, types.Hash{})} {
		if IsJustified(b, target, []RoundChangeSummary{nilRCs[0], nilRCs[1], stale}, nil, 3) {
			t.Fatalf("stale %+v accepted", stale)
		}
	}
	// Prepared round 0 with a zero digest counts as unprepared.
	zero := []RoundChangeSummary{rc(1, 10, 1, roundPtr(0), types.Hash{}), nilRCs[1], nilRCs[2]}
	if !IsJustified(b, target, zero, nil, 3) {
		t.Fatal("prepared round 0 with zero digest")
	}
	// With PREPAREs: a quorum for b in round 0 and one matching ROUND-CHANGE.
	ps := []PrepareSummary{pp(1, 10, 0, b), pp(2, 10, 0, b), pp(3, 10, 0, b)}
	withLock := []RoundChangeSummary{rc(1, 10, 1, roundPtr(0), b), nilRCs[1], nilRCs[2]}
	if !IsJustified(b, target, withLock, ps, 3) {
		t.Fatal("prepared justification")
	}
	if IsJustified(other, target, withLock, ps, 3) {
		t.Fatal("PREPAREs for another digest")
	}
	if IsJustified(b, target, nilRCs, ps, 3) {
		t.Fatal("no matching ROUND-CHANGE")
	}
	if IsJustified(b, target, withLock, ps[:2], 3) {
		t.Fatal("PREPAREs below the quorum")
	}
	mixed := []PrepareSummary{pp(1, 10, 0, b), pp(2, 10, 0, b), pp(3, 10, 1, b)}
	if IsJustified(b, target, withLock, mixed, 3) {
		t.Fatal("PREPAREs of two rounds")
	}
	// A ROUND-CHANGE prepared above the PREPAREs' round is not counted.
	higher := []RoundChangeSummary{rc(1, 10, 1, roundPtr(0), b), rc(2, 10, 1, roundPtr(1), other), nilRCs[2]}
	if IsJustified(b, target, higher, ps, 3) {
		t.Fatal("higher prepared round counted")
	}
	// The sequence of the PREPAREs is not checked.
	otherSeq := []PrepareSummary{pp(1, 7, 0, b), pp(2, 7, 0, b), pp(3, 7, 0, b)}
	if !IsJustified(b, target, withLock, otherSeq, 3) {
		t.Fatal("PREPARE sequence checked")
	}
}

// On these values the truncating accessors are the identity and the
// comparisons they feed agree with full comparisons.
func TestTruncationIdentity(t *testing.T) {
	for _, n := range []uint64{0, 1, 2, 9, 10, 1 << 32, 1<<62 + 5, math.MaxInt64} {
		h := types.HeightFromUint64(n)
		if h.RefLow64() != n || h.RefLowInt64() != int64(n) {
			t.Fatalf("height %d", n)
		}
		if n > 0 {
			last := types.HeightFromUint64(n - 1)
			if !sameAsPrevious(last, h) {
				t.Fatalf("sameAsPrevious(%d, %d)", n-1, n)
			}
		}
		if sameAsPrevious(h, h) {
			t.Fatalf("sameAsPrevious(%d, %d)", n, n)
		}
		r := types.RoundFromUint64(n)
		if roundKey(r) != n {
			t.Fatalf("round key %d", n)
		}
	}
	if sameAsPrevious(types.HeightFromUint64(0), types.HeightFromUint64(0)) {
		t.Fatal("sequence 0 has no previous height")
	}
	// Backlog priority: ROUND-CHANGE first, then by round, then PRE-PREPARE,
	// COMMIT, PREPARE.
	msgs := []*codec.Message{
		{Code: codec.CodePrepare, View: view(10, 1)},
		{Code: codec.CodeCommit, View: view(10, 1)},
		{Code: codec.CodePreprepare, View: view(10, 1)},
		{Code: codec.CodePrepare, View: view(10, 0)},
		{Code: codec.CodeRoundChange, View: view(10, 3)},
		{Code: codec.CodePreprepare, View: view(11, 0)},
	}
	want := []int{4, 3, 2, 1, 0, 5}
	q := &backlogQueue{keys: map[backlogKey]bool{}}
	for i, m := range msgs {
		q.push(backlogEntry{m: &Verified{Msg: m}, prio: backlogPriority(m), seq: uint64(i)})
	}
	for i, e := range q.entries {
		if e.m.Msg != msgs[want[i]] {
			t.Fatalf("position %d: %d %s", i, e.m.Msg.Code, e.m.Msg.View.Round)
		}
	}
	if k := keyOf(msgs[0]); k.sequence != 10 || k.round != 1 || k.code != codec.CodePrepare {
		t.Fatalf("key %+v", k)
	}
}

// Stored requests are released lowest number first.
func TestPendingRequestOrder(t *testing.T) {
	h := newHarness(t, 4, 0)
	h.start()
	b12 := h.block(12, 1, h.addrs[0])
	b11 := h.block(11, 1, h.addrs[0])
	h.step(Request{Block: b12})
	h.step(Request{Block: b11})
	if len(h.s.pending) != 2 || h.s.pending[0].block != b11 {
		t.Fatal("pending order")
	}
	h.env.head = h.proposal(1)
	h.step(NewHead{})
	sch := outputsOf[Schedule](h.out)
	if len(sch) != 1 || sch[0].In.(Request).Block != b11 {
		t.Fatalf("scheduled %v", sch)
	}
}

func TestBuildWait(t *testing.T) {
	const head = 1_700_000_000
	s := int64(time.Second)
	tests := []struct {
		bp    uint64
		round uint64
		now   int64
		want  time.Duration
	}{
		{2, 0, head * s, 2 * time.Second},
		{1, 0, head*s - 3*s, 4 * time.Second},
		{1, 0, head*s + s, 0},
		{1, 0, head*s + 250_000_000, 750 * time.Millisecond},
		{1, 0, head*s + 5_500_000_000, 0},
		{1, 1, head*s + 250_000_000, 0},
		{3, 5, head*s - 10*s, 0},
	}
	for _, tt := range tests {
		if got := BuildWait(head, tt.bp, types.RoundFromUint64(tt.round), tt.now); got != tt.want {
			t.Errorf("bp %d round %d now %d: %v, want %v", tt.bp, tt.round, tt.now, got, tt.want)
		}
	}
	r := RequestBuild{HeadTime: head, BlockPeriod: 2, Round: types.RoundFromUint64(0)}
	if r.Wait(head*s) != 2*time.Second {
		t.Fatal("RequestBuild.Wait")
	}
}

// Stop cancels every timer and discards the state; inputs are ignored until
// Start, which enters the view after the current head again.
func TestStopAndStart(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachPrepared(b)
	out := h.step(Stop{})
	if c := outputsOf[CancelTimers](out); len(c) != 1 || len(c[0].Kinds) != 3 {
		t.Fatalf("stop outputs %v", out)
	}
	if h.s.Vars() != nil || h.s.Running() {
		t.Fatal("state kept after Stop")
	}
	gen := h.s.gen[RoundTimer]
	for _, in := range []Input{Timeout{Kind: RoundTimer, Gen: gen}, NewHead{}, Request{Block: b}, Message{Code: codec.CodePrepare, Payload: h.encode(h.prepare(0, view(10, 0), b))}} {
		if out := h.step(in); len(out) != 0 {
			t.Fatalf("%T while stopped: %v", in, out)
		}
	}
	h.env.head = b
	h.start()
	h.wantView(11, 0, AcceptRequest)
	v := h.vars()
	if v.LockedBlock != nil || v.Certificate != nil || len(v.Backlog) != 0 || len(v.ExtraPrepareSeals) != 0 {
		t.Fatalf("state after restart %+v", v)
	}
	// The round timer of the previous run has no effect.
	if out := h.step(Timeout{Kind: RoundTimer, Gen: gen}); len(out) != 0 {
		t.Fatalf("timer of the previous run: %v", out)
	}
}

// The same inputs with the same answers give equal outputs and state.
func TestDeterministicOutputs(t *testing.T) {
	run := func() ([][]Output, []*Vars) {
		h := newHarness(t, 4, 1)
		var outs [][]Output
		var vars []*Vars
		rec := func(o []Output) {
			outs = append(outs, o)
			vars = append(vars, h.s.Vars())
		}
		b := h.proposal(1)
		rec(h.start())
		for _, i := range []int{0, 2, 3} {
			rec(h.deliver(i, h.prepare(i, view(10, 0), b)))
			rec(h.deliver(i, h.commit(i, view(10, 0), b)))
			rec(h.deliver(i, h.roundChange(i, view(11, 0), nil, nil, nil)))
		}
		rec(h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil)))
		rec(h.selfDeliver(h.broadcasts()[0]))
		rec(h.roundTimeout())
		rec(h.deliver(2, h.roundChange(2, view(10, 1), nil, nil, nil)))
		rec(h.deliver(3, h.roundChange(3, view(10, 1), nil, nil, nil)))
		return outs, vars
	}
	o1, v1 := run()
	for i := 0; i < 5; i++ {
		o2, v2 := run()
		if !reflect.DeepEqual(o1, o2) || !reflect.DeepEqual(v1, v2) {
			t.Fatal("outputs differ between runs")
		}
	}
}

// process_extra_seals selects the stored seals of (head number, prior round)
// with the head's hash, indexed in the prior set.
func TestSnapshotExtraSeals(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachCommitted(b)
	h.deliver(3, h.prepare(3, view(10, 0), b))
	h.deliver(3, h.commit(3, view(10, 0), b))
	h.env.head = b
	h.step(NewHead{})
	snap := h.s.Snapshot()
	if !snap.Running || snap.View.Cmp(view(11, 0)) != 0 || snap.PriorRound.Cmp(types.RoundFromUint64(0)) != 0 {
		t.Fatalf("snapshot %+v", snap)
	}
	prepared, committed := snap.ExtraSeals(b.Header)
	if len(prepared) != 4 || len(committed) != 4 {
		t.Fatalf("extra seals %d %d", len(prepared), len(committed))
	}
	other := h.proposal(2)
	if p, c := snap.ExtraSeals(other.Header); len(p) != 0 || len(c) != 0 {
		t.Fatal("seals for another block")
	}
	h.step(Stop{})
	if p, c := h.s.Snapshot().ExtraSeals(b.Header); len(p) != 0 || len(c) != 0 {
		t.Fatal("seals of a stopped core")
	}
}

// The decision hands exactly the quorum's seals over, and a node outside the
// set sends nothing.
func TestDecisionSealsAndNonMember(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachCommitted(b)
	if len(h.env.lastPrepared) != 3 || len(h.env.lastCommitted) != 3 {
		t.Fatalf("seals %d %d", len(h.env.lastPrepared), len(h.env.lastCommitted))
	}
	c := outputsOf[Commit](h.out)
	if len(c) != 1 || blockHash(c[0].Block) != blockHash(b) {
		t.Fatal("commit output")
	}
	x, err := codec.DecodeExtra(c[0].Block.Header)
	if err != nil || x.PreparedSeal == nil || x.CommittedSeal == nil {
		t.Fatalf("sealed header %v", err)
	}

	n := newHarness(t, 4, -1) // not a validator
	n.start()
	n.deliver(0, n.preprepare(0, view(10, 0), b, nil, nil))
	n.expect(Process, rowPreprepareAccept, true)
	if len(n.broadcasts()) != 0 {
		t.Fatal("a non-member sent a PREPARE")
	}
	n.roundTimeout()
	if len(n.broadcasts()) != 0 {
		t.Fatal("a non-member sent a ROUND-CHANGE")
	}
}

// A PRE-PREPARE that fails to reach the network leaves preprepare_sent as it
// was.
func TestBroadcastFailedPreprepare(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.roundTimeout()
	h.step(Request{Block: h.proposal(5)})
	h.selfDeliver(outputsOf[Broadcast](h.s.Step(h.env, Timeout{Kind: RetryTimer, Round: types.RoundFromUint64(1)}))[0])
	h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
	h.deliver(2, h.roundChange(2, view(10, 1), nil, nil, nil))
	if h.vars().PreprepareSent.Cmp(types.RoundFromUint64(1)) != 0 {
		t.Fatal("PRE-PREPARE not sent")
	}
	h.step(BroadcastFailed{Code: codec.CodePreprepare, View: view(10, 1)})
	if !h.vars().PreprepareSent.IsZero() {
		t.Fatal("preprepare_sent kept after a failed broadcast")
	}
}
