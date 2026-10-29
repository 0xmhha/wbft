package runner

import (
	"errors"
	"log/slog"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestValidatorStartTimerQueueOwnership(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Second, 2 * time.Second} {
		clock := &manualClock{}
		var records []journal.TimerRec
		q := NewTimerQueue(clock)
		q.s.observe = func(rec journal.TimerRec) { records = append(records, rec) }
		q.s.setOwner(1, 2, 3, "core")
		large := new(big.Int).Lsh(big.NewInt(1), 130)
		h := types.MustHeightFromBig(large)
		rnd, err := types.RoundFromBig(large)
		if err != nil {
			t.Fatal(err)
		}
		old := consensus.ArmTimer{Kind: consensus.ValidatorStartTimer,
			View: types.View{Sequence: h, Round: rnd}, Round: rnd, Gen: 4, Duration: 2 * time.Second}
		q.Arm(old, 0)
		if q.Status().Armed != 1 || q.Status().Queued != 0 {
			t.Fatal("fifth slot was not reserved")
		}
		clock.advance(elapsed)
		if q.Pending() != (elapsed == 2*time.Second) {
			t.Fatal("normal timer boundary not exercised")
		}
		q.Clear()
		if q.Pending() || q.Status() != (TimerQueueStatus{}) {
			t.Fatal("clear retained the fifth timer")
		}
		q.s.setOwner(2, 1, 1, "core")
		current := old
		current.Gen++
		current.Duration = 3 * time.Second
		q.Arm(current, clock.Mono())
		clock.advance(elapsed + 2*time.Second)
		if _, ok := q.Pop(); ok {
			t.Fatal("old reservation crossed the new run")
		}
		clock.advance(elapsed + 3*time.Second)
		got, ok := q.Pop()
		if !ok || got.Kind != current.Kind || got.Gen != current.Gen || got.View.Cmp(current.View) != 0 || got.Round.Cmp(current.Round) != 0 {
			t.Fatal("full retry identity lost")
		}
		body, err := inputlog.Encode(got)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := inputlog.Decode(inputlog.KindTimeout, body, nil)
		if err != nil || !reflect.DeepEqual(decoded, got) {
			t.Fatal("existing timeout codec lost kind4 or full integers", err)
		}
		cleared := false
		for _, rec := range records {
			if rec.Action == "cancel" && reflect.DeepEqual(rec.Kinds, []uint64{0, 1, 2, 4}) {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("clear added the inactive proposal slot or missed validator retry")
		}
		q.Clear()
	}
}

func TestValidatorStartTimerReplacementAndQueuedCancellation(t *testing.T) {
	clock := &manualClock{}
	q := NewTimerQueue(clock)
	a := consensus.ArmTimer{Kind: consensus.ValidatorStartTimer, Gen: 1, Duration: time.Second}
	q.Arm(a, 0)
	b := a
	b.Gen, b.Duration = 2, 2*time.Second
	q.Arm(b, 0)
	clock.advance(time.Second)
	if q.Pending() {
		t.Fatal("replaced reservation fired")
	}
	clock.advance(2 * time.Second)
	q.Cancel([]consensus.TimerKind{consensus.ValidatorStartTimer})
	got, ok := q.Pop()
	if !ok || got.Gen != b.Gen {
		t.Fatal("cancel changed the existing queued-expiry contract")
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("duplicate expiry")
	}
	q.Clear()
}

func TestValidatorStartLogicalArmBoundary(t *testing.T) {
	for _, which := range []string{"valid", "overflow", "off", "zero", "duration", "message", "negative", "future_from"} {
		t.Run(which, func(t *testing.T) {
			from := time.Duration(math.MaxInt64) - time.Second
			clock := &manualClock{now: from}
			flags := consensus.ImprovementSet(0).With(consensus.DeferValidatorStart)
			a := consensus.ArmTimer{Kind: consensus.ValidatorStartTimer, Gen: 1, Duration: time.Second}
			switch which {
			case "overflow":
				from++
				clock.now = from
			case "off":
				flags = 0
			case "zero":
				a.Gen = 0
			case "duration":
				a.Duration++
			case "message":
				a.Msg = &consensus.Verified{}
			case "negative":
				from, clock.now = -1, 0
			case "future_from":
				clock.now = from - 1
			}
			r := &Runner{cfg: Config{Core: consensus.Options{Improvements: flags}}, d: Deps{Clock: clock}, log: slog.New(slog.DiscardHandler)}
			r.timers = scheduler{clock: clock}
			ok := r.armTimer(a, from)
			if which == "valid" {
				if !ok || r.Halted() != nil || r.timers.live[consensus.ValidatorStartTimer] == nil {
					t.Fatal("valid arm was rejected")
				}
			} else if ok || !errors.Is(r.Halted(), ErrHalted) || r.timers.live[consensus.ValidatorStartTimer] != nil || len(clock.q) != 0 {
				t.Fatal("invalid logical arm was installed")
			}
			r.timers.clear()
		})
	}
}

func TestValidatorStartCancelsOnlyOwnedOldBuild(t *testing.T) {
	k := newKeys(t, 4)
	clock := &manualClock{}
	head := block(t, 9, 0, k.addrs[3], types.Hash{})
	chain := &fakeChain{head: head.Header, vs: k.vs, clock: clock}
	app := &fakeApp{}
	flags := consensus.ImprovementSet(0).With(consensus.DeferValidatorStart)
	r := &Runner{cfg: Config{Core: consensus.Options{Self: k.addrs[1], Improvements: flags}},
		d: Deps{Clock: clock, Chain: chain, App: app}, log: slog.New(slog.DiscardHandler)}
	r.core = consensus.NewState(r.cfg.Core)
	r.env = &liveEnv{r: r, head: head.Header}
	r.timers = scheduler{clock: clock}
	r.core.Step(r.env, consensus.Start{})
	old := make(chan struct{})
	r.buildDone = old
	r.cancelValidatorStartBuild()
	select {
	case <-old:
		t.Fatal("ready core cancelled an ordinary builder")
	default:
	}
	next := block(t, 10, 1, k.addrs[0], types.Hash{})
	r.env.head, chain.vs = next.Header, nil
	outs := r.core.Step(r.env, consensus.NewHead{Header: next.Header})
	r.cancelValidatorStartBuild()
	select {
	case <-old:
	default:
		t.Fatal("waiting retained old builder ownership")
	}
	if r.buildDone != nil {
		t.Fatal("old build channel was retained")
	}
	r.cancelValidatorStartBuild() // No duplicate close.
	if late := r.core.Step(r.env, consensus.Request{Block: next}); len(late) != 0 {
		t.Fatal("late builder result entered pending core")
	}
	var wait consensus.ArmTimer
	for _, o := range outs {
		if a, ok := o.(consensus.ArmTimer); ok && a.Kind == consensus.ValidatorStartTimer {
			wait = a
		}
	}
	if wait.Gen == 0 {
		t.Fatal("no actual metadata wait")
	}
	chain.vs = k.vs
	outs = r.core.Step(r.env, consensus.Timeout{Kind: wait.Kind, View: wait.View, Round: wait.Round, Gen: wait.Gen})
	r.execute(&stepCtx{outs: outs})
	if r.buildDone == nil || r.buildDone == old || len(app.builds) != 1 || app.builds[0].Height.CmpUint64(11) != 0 {
		t.Fatal("ready height did not receive a fresh owned builder")
	}
	close(r.buildDone)
	r.buildDone = nil
	r.timers.clear()
}

func TestValidatorStartRetainsDeferredMetadataUntilReady(t *testing.T) {
	k := newKeys(t, 4)
	clock := &manualClock{}
	head := block(t, 10, 0, k.addrs[0], types.Hash{})
	chain := &fakeChain{head: head.Header, clock: clock}
	flags := consensus.ImprovementSet(0).With(consensus.DeferValidatorStart)
	r := &Runner{cfg: Config{Core: consensus.Options{Improvements: flags}}, d: Deps{Clock: clock, Chain: chain}}
	r.core = consensus.NewState(r.cfg.Core)
	r.env = &liveEnv{r: r, head: head.Header}
	outs := r.core.Step(r.env, consensus.Start{})
	r.nextHeight = newNextHeightPool(NextHeightLimits{Entries: 4, Bytes: 1024, PerPeer: 4, PerSource: 4})
	p := r.nextHeight
	// These are detached private reservation identities, not packets or
	// signed records. No receiver, WAL append or core message is executed.
	for _, id := range []uint64{11, 12} {
		bookkeeping := []byte("opaque reservation bookkeeping")
		p.entries[id] = &deferredEntry{record: deferredRecord{ID: id, Payload: bookkeeping},
			outer: &consensus.OuterSigner{View: types.View{Sequence: types.HeightFromUint64(id)}}, stage: deferredPending}
		p.order = append(p.order, id)
		p.bytes += uint64(len(bookkeeping))
	}
	beforeEntries, beforeBytes := r.NextHeightUsage()
	if beforeEntries != 2 || beforeBytes == 0 {
		t.Fatal("positive reservation bookkeeping was not exercised")
	}
	if r.core.Snapshot().Running || !r.core.Snapshot().View.Sequence.IsZero() {
		t.Fatal("pending exposed a production view")
	}
	if r.settleNextHeight() {
		t.Fatal("waiting produced a deferred admit or drop")
	}
	if _, ok := r.takeNextHeight(); ok {
		t.Fatal("waiting dispatched deferred metadata")
	}
	if len(p.entries) != 2 || len(p.order) != 2 || p.entries[11].stage != deferredPending || p.entries[12].stage != deferredPending {
		t.Fatal("view zero expired a retained reservation")
	}
	if entries, bytes := r.NextHeightUsage(); entries != beforeEntries || bytes != beforeBytes || p.order[0] != 11 || p.order[1] != 12 {
		t.Fatal("waiting changed positive byte usage or reservation order")
	}
	var a consensus.ArmTimer
	for _, o := range outs {
		if arm, ok := o.(consensus.ArmTimer); ok && arm.Kind == consensus.ValidatorStartTimer {
			a = arm
		}
	}
	chain.vs = k.vs
	r.core.Step(r.env, consensus.Timeout{Kind: a.Kind, View: a.View, Round: a.Round, Gen: a.Gen})
	if r.settleNextHeight() {
		t.Fatal("ready current/future reservation was expired")
	}
	q, ok := r.takeNextHeight()
	if !ok || q.deferred == nil || q.deferred.record.ID != 11 || p.entries[12].stage != deferredPending {
		t.Fatal("ready did not recheck the actual current height")
	}
}
