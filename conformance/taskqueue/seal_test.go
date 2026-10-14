package taskqueue

import (
	"slices"
	"testing"
)

func sealEffects(t *testing.T, got []SealEffect, err error, want ...SealEffect) {
	t.Helper()
	if err != nil || !slices.Equal(got, want) {
		t.Fatal(got, err, "want", want)
	}
}
func sealer(t *testing.T, capacity int) *Sealer {
	t.Helper()
	s, err := NewSealer(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func beginSeal(t *testing.T, s *Sealer, id string, n byte) {
	t.Helper()
	if err := s.Begin(SealRequest{ID: id, Hash: hash(n)}); err != nil {
		t.Fatal(err)
	}
}
func acquireSeal(t *testing.T, s *Sealer, id string) {
	t.Helper()
	got, err := s.Acquire(id)
	sealEffects(t, got, err, SealEffect{ID: id, Kind: MutexAcquired})
}
func cancelSeal(t *testing.T, s *Sealer, id string) {
	t.Helper()
	if err := s.Cancel(id); err != nil {
		t.Fatal(err)
	}
}
func stopSeal(t *testing.T, s *Sealer, id string) {
	t.Helper()
	got, err := s.ChooseStop(id)
	sealEffects(t, got, err, SealEffect{ID: id, Kind: ResultSelected, Cancelled: true})
}
func sendStop(t *testing.T, s *Sealer, id string) {
	t.Helper()
	got, err := s.SendResult(id)
	sealEffects(t, got, err, SealEffect{ID: id, Kind: ResultSent, Cancelled: true})
}
func releaseSeal(t *testing.T, s *Sealer, id string) {
	t.Helper()
	got, err := s.Release(id)
	sealEffects(t, got, err, SealEffect{ID: id, Kind: MutexReleased})
}
func TestSealReturnPostResultAndUnlockAreSeparate(t *testing.T) {
	s := sealer(t, 10)
	beginSeal(t, s, "one", 1)
	if _, err := s.BeginPost("one"); err == nil {
		t.Fatal("post before invocation entered")
	}
	acquireSeal(t, s, "one")
	if s.ProposedHash() != hash(1) || s.Phase("one") != WaitingChoice || !s.PostPending("one") {
		t.Fatal("acquire changed")
	}
	if _, err := s.ChooseStop("one"); err == nil {
		t.Fatal("stop invented")
	}
	got, err := s.OfferCommit(Commit{ID: "other", Hash: hash(2)})
	sealEffects(t, got, err, SealEffect{Commit: "other", Kind: CommitForwarded})
	got, err = s.OfferCommit(Commit{ID: "committed", Hash: hash(1), SealHash: hash(3)})
	sealEffects(t, got, err, SealEffect{Commit: "committed", Kind: CommitAccepted})
	got, err = s.ChooseCommit("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Commit: "committed", Kind: ResultSelected})
	got, err = s.SendResult("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Commit: "committed", Kind: ResultSent})
	if s.Owner() != "one" || s.Phase("one") != WaitingRelease {
		t.Fatal("send implicitly released mutex")
	}
	result, err := s.ReceiveResult()
	if err != nil || result.ID != "one" || result.Commit != "committed" || result.Hash != hash(1) || result.SealHash != hash(3) || result.Cancelled {
		t.Fatal(result, err)
	}
	releaseSeal(t, s, "one")
	if s.ProposedHash() != hash(0) || s.Phase("one") != SealFinished {
		t.Fatal("deferred cleanup missing")
	}
	got, err = s.BeginPost("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestPostEntered})
	if _, err = s.BeginPost("one"); err == nil {
		t.Fatal("posted twice")
	}
	got, err = s.DeliverPost("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestDelivered})
	got, err = s.ReturnPost("one", true)
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestPostReturned})
	if _, err = s.ReturnPost("one", true); err == nil {
		t.Fatal("post returned twice")
	}

}
func TestResultBackpressureRetainsMutexAndStoppedWaiterStillPosts(t *testing.T) {
	s := sealer(t, 1)
	beginSeal(t, s, "one", 1)
	acquireSeal(t, s, "one")
	cancelSeal(t, s, "one")
	stopSeal(t, s, "one")
	sendStop(t, s, "one")
	releaseSeal(t, s, "one")
	beginSeal(t, s, "two", 2)
	cancelSeal(t, s, "two")
	acquireSeal(t, s, "two")
	if !s.PostPending("two") {
		t.Fatal("pre-closed stop suppressed asynchronous request post")
	}
	stopSeal(t, s, "two")
	if _, err := s.SendResult("two"); err == nil || s.Owner() != "two" || s.Phase("two") != WaitingResult {
		t.Fatal("full result channel released sender")
	}
	beginSeal(t, s, "three", 3)
	if _, err := s.Acquire("three"); err == nil {
		t.Fatal("waiter bypassed held mutex")
	}
	if _, err := s.Release("two"); err == nil {
		t.Fatal("release before result send")
	}
	r, err := s.ReceiveResult()
	if err != nil || r.ID != "one" || !r.Cancelled {
		t.Fatal(r, err)
	}
	sendStop(t, s, "two")
	releaseSeal(t, s, "two")
	acquireSeal(t, s, "three")
	r, err = s.ReceiveResult()
	if err != nil || r.ID != "two" || !r.Cancelled {
		t.Fatal(r, err)
	}
}
func TestBlockedCommitKeepsRouteAcrossProposalReplacement(t *testing.T) {
	s := sealer(t, 10)
	beginSeal(t, s, "one", 1)
	acquireSeal(t, s, "one")
	got, err := s.OfferCommit(Commit{ID: "first", Hash: hash(1)})
	sealEffects(t, got, err, SealEffect{Commit: "first", Kind: CommitAccepted})
	got, err = s.OfferCommit(Commit{ID: "second", Hash: hash(1)})
	sealEffects(t, got, err)
	if !s.CommitBlocked() {
		t.Fatal("capacity-one channel accepted second producer")
	}
	cancelSeal(t, s, "one")
	stopSeal(t, s, "one")
	sendStop(t, s, "one")
	releaseSeal(t, s, "one")
	beginSeal(t, s, "two", 2)
	acquireSeal(t, s, "two")
	got, err = s.ChooseCommit("two")
	sealEffects(t, got, err, SealEffect{ID: "two", Commit: "first", Kind: CommitDiscarded})
	got, err = s.AcceptCommit()
	sealEffects(t, got, err, SealEffect{Commit: "second", Kind: CommitAccepted})
	got, err = s.ChooseCommit("two")
	sealEffects(t, got, err, SealEffect{ID: "two", Commit: "second", Kind: CommitDiscarded})
	if s.Phase("two") != WaitingChoice || s.CommitBlocked() {
		t.Fatal("discard fabricated completion or rerouted pending send")
	}
}
func TestReadyStopAndCommitHaveExplicitChoice(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "stop"}[stop], func(t *testing.T) {
			s := sealer(t, 10)
			beginSeal(t, s, "one", 1)
			acquireSeal(t, s, "one")
			cancelSeal(t, s, "one")
			got, err := s.OfferCommit(Commit{ID: "c", Hash: hash(1)})
			sealEffects(t, got, err, SealEffect{Commit: "c", Kind: CommitAccepted})
			if !s.StopReady("one") || !s.CommitReady() {
				t.Fatal("selection candidates missing")
			}
			if stop {
				stopSeal(t, s, "one")
			} else {
				got, err = s.ChooseCommit("one")
				sealEffects(t, got, err, SealEffect{ID: "one", Commit: "c", Kind: ResultSelected})
			}
			if _, err = s.ChooseCommit("one"); err == nil {
				t.Fatal("selected twice")
			}
			if s.CommitReady() != stop {
				t.Fatal("stop consumed commit or commit retained consumed value")
			}
		})
	}
}

func TestBlockedPostSurvivesCancelledSeal(t *testing.T) {
	s := sealer(t, 10)
	beginSeal(t, s, "one", 1)
	acquireSeal(t, s, "one")
	got, err := s.BeginPost("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestPostEntered})
	if _, err = s.ReturnPost("one", true); err == nil {
		t.Fatal("blocked subscriber handoff completed implicitly")
	}
	cancelSeal(t, s, "one")
	stopSeal(t, s, "one")
	sendStop(t, s, "one")
	releaseSeal(t, s, "one")
	if s.PostPhase("one") != PostEntered {
		t.Fatal("Seal completion erased outstanding post")
	}
	got, err = s.DeliverPost("one")
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestDelivered})
	got, err = s.ReturnPost("one", true)
	sealEffects(t, got, err, SealEffect{ID: "one", Kind: RequestPostReturned})
	beginSeal(t, s, "two", 2)
	acquireSeal(t, s, "two")
	got, err = s.BeginPost("two")
	sealEffects(t, got, err, SealEffect{ID: "two", Kind: RequestPostEntered})
	got, err = s.ReturnPost("two", false)
	sealEffects(t, got, err, SealEffect{ID: "two", Kind: RequestPostReturned})
	if _, err = s.DeliverPost("two"); err == nil {
		t.Fatal("absent subscriber became delivered input")
	}
}
