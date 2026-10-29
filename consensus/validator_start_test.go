package consensus

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// These tests change read-only metadata availability in a pure core. They
// do not interrupt an actor, transport, store, signer or running network.
type validatorStartEnv struct {
	*fakeEnv
	set   *validator.Set
	err   error
	calls int
}

func (e *validatorStartEnv) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	e.calls++
	return e.set, e.err
}

func validatorStartHarness(t *testing.T, flags ImprovementSet) (*harness, *validatorStartEnv) {
	t.Helper()
	h := newHarness(t, 4, 1)
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[1], Improvements: flags})
	return h, &validatorStartEnv{fakeEnv: h.env, set: h.vs}
}

func validatorStartArm(t *testing.T, outs []Output) ArmTimer {
	t.Helper()
	var found []ArmTimer
	for _, a := range outputsOf[ArmTimer](outs) {
		if a.Kind == ValidatorStartTimer {
			found = append(found, a)
		}
	}
	if len(found) != 1 || found[0].Duration != time.Second {
		t.Fatalf("expected one fixed local retry: %+v", found)
	}
	return found[0]
}

func validatorStartExpiry(a ArmTimer) Timeout {
	return Timeout{Kind: a.Kind, View: a.View, Round: a.Round, Gen: a.Gen}
}

func assertNoProduction(t *testing.T, outs []Output) {
	t.Helper()
	for _, o := range outs {
		switch o.(type) {
		case Broadcast, Commit, Relay, Schedule, RequestBuild:
			t.Fatalf("unexpected production while unavailable: %T", o)
		}
	}
}

func TestValidatorStartAvailability(t *testing.T) {
	for _, flags := range []ImprovementSet{0, ImprovementSet(0).With(DeferValidatorStart), KnownImprovements()} {
		for _, outcome := range []string{"error", "nil", "empty", "ready", "error_with_set"} {
			t.Run(flagsName(flags)+"/"+outcome, func(t *testing.T) {
				h, env := validatorStartHarness(t, flags)
				switch outcome {
				case "error", "error_with_set":
					env.err = errors.New("normal metadata is not available yet")
				case "nil":
					env.set = nil
				case "empty":
					var err error
					env.set, err = validator.NewSet(nil, nil, types.ProposerPolicy{})
					if err != nil {
						t.Fatal(err)
					}
				}
				if outcome == "error" {
					env.set = nil
				}
				outs := h.s.Step(env, Start{})
				unavailable := flags.Has(DeferValidatorStart) && (env.err != nil || env.set == nil)
				if (h.s.ValidatorStartWait() != nil) != unavailable || h.s.Snapshot().Running == unavailable {
					t.Fatal("availability was conflated with an empty set")
				}
				// Fresh Start has no stored work from which to produce an own vote.
				for _, o := range outs {
					switch o.(type) {
					case Broadcast, Commit, Relay, Schedule:
						t.Fatalf("fresh Start produced %T", o)
					}
				}
				if unavailable {
					assertNoProduction(t, outs)
					a := validatorStartArm(t, outs)
					if a.Gen != 1 || a.Digest != codec.BlockHash(env.head.Header) || a.View.Sequence.CmpUint64(10) != 0 || h.s.cur != nil || !h.s.Running() || h.s.Vars() != nil {
						t.Fatal("initial wait is not isolated")
					}
					env.set, env.err = h.vs, nil
					outs = h.s.Step(env, validatorStartExpiry(a))
					if h.s.ValidatorStartWait() != nil || !h.s.Snapshot().Running || len(outputsOf[RequestBuild](outs)) != 1 {
						t.Fatal("exact ready retry did not enter the height")
					}
					if h.s.gen[ValidatorStartTimer] != a.Gen {
						t.Fatal("success fabricated another retry generation")
					}
				}
			})
		}
	}
}

func flagsName(flags ImprovementSet) string {
	if flags == 0 {
		return "off"
	}
	if flags == KnownImprovements() {
		return "all"
	}
	return "selected"
}

func TestValidatorStartPreservesOldStateAndBlocksOldInputs(t *testing.T) {
	h, env := validatorStartHarness(t, ImprovementSet(0).With(DeferValidatorStart))
	h.s.Step(env, Start{})
	// Opaque prior state remains owned by its old height while waiting.
	old := h.s.cur
	old.preparedRound = roundPtr(3)
	old.preparedBlock = h.proposal(7)
	oldHead, oldSet := h.s.head, h.s.validators
	h.s.seen[seenKey{}] = seenEntry{}
	env.head, env.set = h.proposal(1), nil
	outs := h.s.Step(env, NewHead{Header: env.head.Header})
	assertNoProduction(t, outs)
	a := validatorStartArm(t, outs)
	if h.s.cur != old || h.s.head.Header != oldHead.Header || h.s.validators != oldSet || old.preparedBlock == nil || len(h.s.seen) != 1 {
		t.Fatal("partially adopted a new height")
	}
	snap := h.s.Snapshot()
	if snap.Running || snap.Validators != nil || snap.IsProposer || snap.Proposer != (types.Address{}) || len(snap.ExtraPrepare) != 0 || snap.ValidatorStart == nil || h.s.Vars() != nil {
		t.Fatal("old producer authority is visible")
	}
	snap.ValidatorStart.Reason = "changed by observer"
	if h.s.ValidatorStartWait().Reason != "validator_set_unavailable" {
		t.Fatal("mutable wait observation")
	}
	for _, in := range []Input{Start{}, Request{Block: h.proposal(2)}, Message{}, Replay{}, CommitResult{}, BroadcastFailed{}, PeerConnected{}, Timeout{Kind: RoundTimer, Gen: h.s.gen[RoundTimer]}, Timeout{Kind: RetryTimer}, Timeout{Kind: FutureTimer}, Timeout{Kind: RoundProposalTimer}} {
		calls := env.calls
		if got := h.s.Step(env, in); len(got) != 0 || env.calls != calls || h.s.cur != old {
			t.Fatalf("old input changed a pending core: %T", in)
		}
	}
	// A failed retry replaces its generation; its old expiry cannot retry again.
	outs = h.s.Step(env, validatorStartExpiry(a))
	b := validatorStartArm(t, outs)
	if b.Gen != a.Gen+1 {
		t.Fatal("retry did not replace its generation")
	}
	if got := h.s.Step(env, validatorStartExpiry(a)); len(got) != 0 {
		t.Fatal("stale expiry was accepted")
	}
	env.set = h.vs
	outs = h.s.Step(env, validatorStartExpiry(b))
	if h.s.ValidatorStartWait() != nil || h.s.cur == old || h.s.cur.view.Sequence.CmpUint64(11) != 0 || len(outputsOf[RequestBuild](outs)) != 1 {
		t.Fatal("ready target was not adopted")
	}
	if got := h.s.Step(env, validatorStartExpiry(b)); len(got) != 0 {
		t.Fatal("successful wait was revived")
	}
}

func TestValidatorStartTargetAndFullView(t *testing.T) {
	h, env := validatorStartHarness(t, ImprovementSet(0).With(DeferValidatorStart))
	large := new(big.Int).Lsh(big.NewInt(1), 130)
	env.head.Header.Number = types.MustHeightFromBig(new(big.Int).Add(large, big.NewInt(9)))
	env.set = nil
	a := validatorStartArm(t, h.s.Step(env, Start{}))
	want := h.s.ValidatorStartWait()
	for _, tmo := range []Timeout{{Kind: ValidatorStartTimer, Gen: a.Gen, View: view(10, 0)}, {Kind: ValidatorStartTimer, Gen: a.Gen, View: a.View, Round: types.RoundFromUint64(1)}, {Kind: ValidatorStartTimer, Gen: a.Gen + 1, View: a.View}} {
		if len(h.s.Step(env, tmo)) != 0 {
			t.Fatal("partial retry identity accepted")
		}
	}
	originalHead := env.head
	other := *env.head.Header
	other.Time++
	env.head = &types.Block{Header: &other}
	if len(h.s.Step(env, NewHead{Header: &other})) != 0 {
		t.Fatal("another parent unlocked waiting")
	}
	env.head = h.block(8, 0, h.addrs[0])
	if len(h.s.Step(env, NewHead{Header: env.head.Header})) != 0 {
		t.Fatal("head rollback replaced target")
	}
	env.head = originalHead
	if len(h.s.Step(env, NewHead{Header: env.head.Header})) != 0 || !reflect.DeepEqual(want, h.s.ValidatorStartWait()) {
		t.Fatal("duplicate notification reset the retry rate")
	}
	next := *originalHead.Header
	next.Number = next.Number.AddUint64(1)
	env.head = &types.Block{Header: &next}
	b := validatorStartArm(t, h.s.Step(env, NewHead{Header: &next}))
	if b.Gen != a.Gen+1 || b.View.Sequence.Cmp(a.View.Sequence.AddUint64(1)) != 0 {
		t.Fatal("new target or full height lost")
	}
	if len(h.s.Step(env, validatorStartExpiry(a))) != 0 {
		t.Fatal("old target expiry revived")
	}
}

func TestValidatorStartMismatchedHeadKeepsRetryLive(t *testing.T) {
	for _, lower := range []bool{false, true} {
		h, env := validatorStartHarness(t, ImprovementSet(0).With(DeferValidatorStart))
		env.set = nil
		original := env.head
		a := validatorStartArm(t, h.s.Step(env, Start{}))
		other := *original.Header
		if lower {
			other.Number = types.HeightFromUint64(8)
		} else {
			other.Time++
		}
		env.head = &types.Block{Header: &other}
		if len(h.s.Step(env, NewHead{Header: &other})) != 0 {
			t.Fatal("unapproved head adopted")
		}
		calls := env.calls
		outs := h.s.Step(env, validatorStartExpiry(a))
		assertNoProduction(t, outs)
		b := validatorStartArm(t, outs)
		if env.calls != calls || b.Gen != a.Gen+1 || b.Digest != a.Digest || b.View.Cmp(a.View) != 0 {
			t.Fatal("unapproved head changed target or silently consumed the only retry")
		}
		env.head, env.set = original, h.vs
		if len(h.s.Step(env, NewHead{Header: original.Header})) != 0 {
			t.Fatal("duplicate head bypassed retry interval")
		}
		outs = h.s.Step(env, validatorStartExpiry(b))
		if h.s.ValidatorStartWait() != nil || !h.s.Snapshot().Running || len(outputsOf[RequestBuild](outs)) != 1 {
			t.Fatal("restored target remained permanently waiting")
		}
	}
}

func TestValidatorStartSameStepRoundChangeAndRequestedRound(t *testing.T) {
	for _, reset := range []bool{false, true} {
		flags := ImprovementSet(0).With(DeferValidatorStart)
		if reset {
			flags = flags.With(ResetHeightState)
		}
		h, env := validatorStartHarness(t, flags)
		outs := h.s.Step(env, Start{})
		var round ArmTimer
		for _, a := range outputsOf[ArmTimer](outs) {
			if a.Kind == RoundTimer {
				round = a
			}
		}
		old := h.s.cur
		largeRound, err := types.RoundFromBig(new(big.Int).Lsh(big.NewInt(1), 130))
		if err != nil {
			t.Fatal(err)
		}
		old.view.Round = largeRound
		env.head, env.set = h.proposal(1), nil
		outs = h.s.Step(env, Timeout{Kind: RoundTimer, Gen: round.Gen, View: old.view})
		assertNoProduction(t, outs)
		a := validatorStartArm(t, outs)
		if a.Round.Cmp(largeRound.AddUint64(1)) != 0 || h.s.cur != old {
			t.Fatal("requested round was truncated")
		}
		env.set = h.vs
		outs = h.s.Step(env, validatorStartExpiry(a))
		builds := outputsOf[RequestBuild](outs)
		wantRound := a.Round
		if reset {
			wantRound = types.Round{}
		}
		if len(builds) != 1 || builds[0].Round.Cmp(wantRound) != 0 {
			t.Fatal("separate reset policy changed")
		}
		if current := h.s.RestoreBuildRequest(); current == nil || current.Round.Cmp(builds[0].Round) != 0 || current.Height.Cmp(builds[0].Height) != 0 {
			t.Fatal("restore inferred the requested round instead of retaining the actual build")
		}
		found := false
		for _, e := range outputsOf[Event](outs) {
			if e.Record.Kind == event.RoundEnter {
				found = e.Record.Fields["cause"] == causeTimeout && e.Record.Fields["requested_round"] == a.Round.String()
			}
		}
		if !found {
			t.Fatal("retry lost original transition cause")
		}
		votes := outputsOf[Broadcast](outs)
		if reset && len(votes) != 0 || !reset && (len(votes) != 1 || votes[0].Msg.Code != codec.CodeRoundChange || votes[0].Msg.View.Sequence.CmpUint64(11) != 0 || votes[0].Msg.View.Round.Cmp(a.Round) != 0) {
			t.Fatal("retry did not preserve its original caller continuation")
		}
	}
}

func TestValidatorStartReadOnlyRestoreAuthority(t *testing.T) {
	h, env := validatorStartHarness(t, ImprovementSet(0).With(DeferValidatorStart))
	if _, ok := h.s.AdoptedView(); ok || h.s.RestoreBuildRequest() != nil {
		t.Fatal("stopped core has restore authority")
	}
	h.s.Step(env, Start{})
	want, ok := h.s.AdoptedView()
	if !ok || want.Cmp(view(10, 0)) != 0 {
		t.Fatal("actual adopted view missing")
	}
	request := h.s.RestoreBuildRequest()
	if request == nil || request.Height.CmpUint64(10) != 0 {
		t.Fatal("seed-only current build missing")
	}
	request.Height = types.HeightFromUint64(99)
	if h.s.RestoreBuildRequest().Height.CmpUint64(10) != 0 {
		t.Fatal("restore intent shares mutable storage")
	}
	h.s.cur.preprepareSent = types.Round{}
	h.s.cur.preprepareSentValid = true
	if h.s.RestoreBuildRequest() != nil {
		t.Fatal("round-zero sent marker was treated as unsent")
	}
	h.s.cur.preprepareSentValid = false
	h.s.cur.pendingRequest = h.proposal(1)
	if h.s.RestoreBuildRequest() != nil {
		t.Fatal("pending builder proposal was replaced")
	}
	h.s.cur.pendingRequest = nil
	h.s.cur.preparedBlock = h.proposal(1)
	if h.s.RestoreBuildRequest() != nil {
		t.Fatal("prepared proposal acquired a new builder")
	}
	h.s.cur.preparedBlock = nil
	env.head, env.set = h.proposal(2), nil
	h.s.Step(env, NewHead{Header: env.head.Header})
	if retained, ok := h.s.AdoptedView(); !ok || retained.Cmp(want) != 0 || h.s.Snapshot().Running || h.s.RestoreBuildRequest() != nil {
		t.Fatal("suspended old view was confused with production readiness")
	}
	h.s.Step(env, Stop{})
	if _, ok := h.s.AdoptedView(); ok || h.s.RestoreBuildRequest() != nil {
		t.Fatal("Stop retained restore intent")
	}
	off, offEnv := validatorStartHarness(t, 0)
	off.s.Step(offEnv, Start{})
	if off.s.RestoreBuildRequest() != nil {
		t.Fatal("default path enabled selected build tracking")
	}
}

func TestValidatorStartFPlusOneRelayAndContinuation(t *testing.T) {
	for _, reset := range []bool{false, true} {
		flags := ImprovementSet(0).With(DeferValidatorStart)
		if reset {
			flags = flags.With(ResetHeightState)
		}
		h, env := validatorStartHarness(t, flags)
		h.s.Step(env, Start{})
		// Replay consumes already-verified metadata; no packet or signature
		// is generated or changed in this pure handler test.
		first := &Verified{Msg: &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, Source: h.addrs[0]}
		h.s.Step(env, Replay{Msg: first})
		env.head, env.set = h.proposal(1), nil
		second := &Verified{Msg: &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, Source: h.addrs[2]}
		outs := h.s.Step(env, Replay{Msg: second})
		assertNoProduction(t, outs)
		a := validatorStartArm(t, outs)
		if wait := h.s.ValidatorStartWait(); wait == nil || !wait.RoundChangeOnResume || wait.Cause != causeFPlusOne {
			t.Fatal("F+1 wait lost its continuation")
		}
		outcomes := outputsOf[Outcome](outs)
		if len(outcomes) != 1 || outcomes[0].Relayed {
			t.Fatal("F+1 waiting reported an old relay")
		}
		// Another unavailable read must keep the same continuation.
		a = validatorStartArm(t, h.s.Step(env, validatorStartExpiry(a)))
		env.set = h.vs
		outs = h.s.Step(env, validatorStartExpiry(a))
		votes := outputsOf[Broadcast](outs)
		if reset && len(votes) != 0 || !reset && (len(votes) != 1 || votes[0].Msg.View.Cmp(view(11, 1)) != 0) {
			t.Fatal("F+1 continuation changed a separate reset policy")
		}
		if h.s.ValidatorStartWait() != nil || len(outputsOf[RequestBuild](outs)) != 1 {
			t.Fatal("F+1 did not resume")
		}
	}
}

func TestValidatorStartCommitResultHeadAdvanceAndOrdinaryStop(t *testing.T) {
	flags := ImprovementSet(0).With(DeferValidatorStart).With(AdvanceOnCommitFailure)
	h, env := validatorStartHarness(t, flags)
	h.s.Step(env, Start{})
	// The result metadata belongs to the current decided view. No actor,
	// application, signer or storage failure is executed by this model.
	h.s.state = Committed
	hash := types.Hash{7}
	h.s.cur.importHash = &hash
	v := h.s.cur.view
	env.head, env.set = h.proposal(1), nil
	outs := h.s.Step(env, CommitResult{Hash: hash, View: &v, Err: errors.New("recorded import result")})
	assertNoProduction(t, outs)
	a := validatorStartArm(t, outs)
	if wait := h.s.ValidatorStartWait(); wait == nil || wait.Cause != causeNewHead || wait.RoundChangeOnResume {
		t.Fatal("already advanced head used finalize-fail continuation")
	}
	oldGen := a.Gen
	outs = h.s.Step(env, Stop{})
	if len(outputsOf[CancelTimers](outs)) != 1 || h.s.Running() || h.s.ValidatorStartWait() != nil {
		t.Fatal("ordinary Stop retained readiness authority")
	}
	a = validatorStartArm(t, h.s.Step(env, Start{}))
	if a.Gen != oldGen+1 {
		t.Fatal("new core run reused the old wait generation")
	}
	if len(h.s.Step(env, Timeout{Kind: ValidatorStartTimer, View: a.View, Round: a.Round, Gen: oldGen})) != 0 {
		t.Fatal("old run retry revived")
	}
	env.set = h.vs
	outs = h.s.Step(env, validatorStartExpiry(a))
	if len(outputsOf[Broadcast](outs)) != 0 || len(outputsOf[RequestBuild](outs)) != 1 {
		t.Fatal("fresh run acquired an old continuation")
	}
}

func TestValidatorStartRetiresPreWaitCallbacksAfterReady(t *testing.T) {
	// The legacy retry/future behavior is retained by the original reference
	// tests. Here only a real readiness suspension retires their old tokens.
	flags := ImprovementSet(0).With(DeferValidatorStart).With(ValidateRoundProposals)
	h, env := validatorStartHarness(t, flags)
	outs := h.s.Step(env, Start{})
	var old []Timeout
	for _, a := range outputsOf[ArmTimer](outs) {
		old = append(old, validatorStartExpiry(a))
	}
	st := &step{s: h.s, env: env}
	st.armRetryTimer()
	st.armFutureTimer(&Verified{Msg: &codec.Message{Code: codec.CodePreprepare, View: view(11, 0), Proposal: h.block(11, 2, h.addrs[0])}}, time.Second)
	for _, a := range outputsOf[ArmTimer](st.out) {
		tmo := validatorStartExpiry(a)
		tmo.Msg = a.Msg
		old = append(old, tmo)
	}
	// A zero-generation optional timer is also below the retired boundary.
	old = append(old, Timeout{Kind: RoundProposalTimer, View: h.s.cur.view})
	env.head, env.set = h.proposal(1), nil
	a := validatorStartArm(t, h.s.Step(env, NewHead{Header: env.head.Header}))
	env.set = h.vs
	h.s.Step(env, validatorStartExpiry(a))
	for _, tmo := range old {
		if got := h.s.Step(env, tmo); len(got) != 0 {
			t.Fatalf("pre-wait callback regained authority: %s", tmo.Kind)
		}
	}
	h.s.Step(env, Stop{})
	outs = h.s.Step(env, Start{})
	for _, tmo := range old {
		if got := h.s.Step(env, tmo); len(got) != 0 {
			t.Fatalf("lifecycle reset revived pre-wait callback: %s", tmo.Kind)
		}
	}
	var round ArmTimer
	for _, a := range outputsOf[ArmTimer](outs) {
		if a.Kind == RoundTimer {
			round = a
		}
	}
	if round.Kind != RoundTimer || round.Gen == 0 {
		t.Fatal("ready state has no new round timer")
	}
	outs = h.s.Step(env, validatorStartExpiry(round))
	if h.s.cur.view.Cmp(view(11, 1)) != 0 || len(outputsOf[Broadcast](outs)) != 1 {
		t.Fatal("retirement also blocked a fresh current timer")
	}
}

func TestValidatorStartStopOverflowAndCheckpoint(t *testing.T) {
	flags := ImprovementSet(0).With(DeferValidatorStart)
	h, env := validatorStartHarness(t, flags)
	if err := h.s.RestoreTimerGenerations([]uint64{2, 3, 4, 0, math.MaxUint64}); err != nil {
		t.Fatal(err)
	}
	env.set = nil
	outs := h.s.Step(env, Start{})
	assertNoProduction(t, outs)
	if len(outputsOf[ArmTimer](outs)) != 0 || h.s.ValidatorStartWait().Live || h.s.ValidatorStartWait().Reason != "validator_start_generation_exhausted" || h.s.gen[4] != math.MaxUint64 || !h.s.Running() {
		t.Fatal("generation wrapped or exhausted wait hidden")
	}
	h.s.Step(env, Stop{})
	if h.s.Running() || h.s.ValidatorStartWait() != nil || h.s.gen[4] != math.MaxUint64 {
		t.Fatal("Stop reset generations or retained wait")
	}
	for _, flags := range []ImprovementSet{0, flags, flags.With(ValidateRoundProposals)} {
		s := NewState(Options{Improvements: flags})
		for _, bad := range [][]uint64{{1, 2}, {1, 2, 3, 1, 5, 6}} {
			before := s.TimerGenerations()
			if s.RestoreTimerGenerations(bad) == nil || !reflect.DeepEqual(before, s.TimerGenerations()) {
				t.Fatal("invalid checkpoint changed state")
			}
		}
		if flags.Has(DeferValidatorStart) {
			if s.RestoreTimerGenerations([]uint64{1, 2, 3}) == nil {
				t.Fatal("incomplete selected checkpoint accepted")
			}
			proposal := uint64(0)
			if flags.Has(ValidateRoundProposals) {
				proposal = 4
			} else if s.RestoreTimerGenerations([]uint64{1, 2, 3, 4, 5}) == nil {
				t.Fatal("inactive proposal slot accepted")
			}
			if err := s.RestoreTimerGenerations([]uint64{1, 2, 3, proposal, 5}); err != nil {
				t.Fatal(err)
			}
			if len(s.TimerGenerations()) != 5 || s.TimerGens() != [3]uint64{1, 2, 3} || s.AllTimerGens() != [4]uint64{1, 2, 3, proposal} {
				t.Fatal("legacy API or full width changed")
			}
			s.RestoreTimerGens([3]uint64{6, 7, 8})
			if !reflect.DeepEqual(s.TimerGenerations(), []uint64{1, 2, 3, proposal, 5}) {
				t.Fatal("incomplete legacy restore changed a selected profile")
			}
			if s.RestoreTimerGenerations([]uint64{1, 2, 3, proposal, 4}) == nil || s.gen[4] != 5 {
				t.Fatal("selected restore rolled back readiness generation")
			}
		}
	}
	// Optional state leaves the reference JSON field set unchanged.
	data, err := json.Marshal(NewState(Options{}).Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if _, ok := object["validator_start"]; ok {
		t.Fatal("off snapshot acquired an optional field")
	}
	if !KnownImprovements().Has(DeferValidatorStart) || RestartSafety.Has(DeferValidatorStart) || DeferValidatorStart != CheckEpochInfoPresence+1 {
		t.Fatal("selection changed existing defaults or bit order")
	}
	if k, ok := ParseImprovement("defer_validator_start"); !ok || k != DeferValidatorStart || ValidatorStartTimer.String() != "validator_start" {
		t.Fatal("explicit selection is not named")
	}
}
