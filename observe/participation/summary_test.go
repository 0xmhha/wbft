package participation

import (
	"reflect"
	"testing"
	"time"
)

// TestSummarize aggregates four heights of three validators: height 1
// local and decided at round 0, height 2 a gap, height 3 from the headers
// and decided at round 1, height 4 local and decided at round 2 after a
// timeout this node saw in round 0 (it never entered round 1).
func TestSummarize(t *testing.T) {
	ms := func(d int64) *int64 { return &d }
	now := time.Unix(1, 0)
	recs := []Record{
		{Height: "1", Source: "local", Round: "0", Proposer: "a0",
			Rounds: []Round{{Round: "0", Proposer: "a0", Outcome: "committed", Entered: &now}},
			Validators: []ValidatorRound{
				{Round: "0", Validator: "a0", InPrevCommitted: true, Prepare: &Seen{Via: "self", DelayMs: ms(5)}},
				{Round: "0", Validator: "a1", InPrevCommitted: true, Prepare: &Seen{Via: "direct", DelayMs: ms(10)}, Commit: &Seen{Via: "direct", DelayMs: ms(20)}},
				{Round: "0", Validator: "a2", InPrevCommitted: true, Extra: true, Prepare: &Seen{Via: "direct", DelayMs: ms(30)}},
			}},
		{Height: "2", Gap: true},
		{Height: "3", Source: "header", Round: "1", Proposer: "a2",
			Rounds: []Round{{Round: "0", Proposer: "a1", Outcome: "round_change"}, {Round: "1", Proposer: "a2", Outcome: "committed"}},
			Validators: []ValidatorRound{
				{Round: "1", Validator: "a0", InPrevCommitted: true},
				{Round: "1", Validator: "a1", Evidence: true},
				{Round: "1", Validator: "a2", InPrevCommitted: true, Prepare: &Seen{Via: "backlog", DelayMs: ms(50)}},
			}},
		{Height: "4", Source: "local", Round: "2", Proposer: "a1",
			Rounds: []Round{{Round: "0", Proposer: "a2", Outcome: "round_change", Entered: &now},
				{Round: "1", Proposer: "a0", Outcome: "round_change"},
				{Round: "2", Proposer: "a1", Outcome: "committed", Entered: &now, Cause: "timeout"}},
			Validators: []ValidatorRound{
				{Round: "2", Validator: "a0", InPrevCommitted: true},
				{Round: "2", Validator: "a1", InPrevCommitted: true},
				{Round: "2", Validator: "a2", InPrevCommitted: true},
			}},
	}
	s := Summarize(recs)
	if s.From != "1" || s.To != "4" || s.Heights != 3 || s.Gaps != 1 || s.Local != 2 || len(s.Validators) != 3 {
		t.Fatalf("summary %+v", s)
	}
	want := []ValidatorSummary{
		{Validator: "a0", Heights: 3, ProposerRounds: 2, Proposed: 1, Missed: 1, Sealed: 3, Delays: map[string]Delay{}},
		{Validator: "a1", Heights: 3, ProposerRounds: 2, Proposed: 1, Missed: 1, Sealed: 2, Evidence: 1,
			Delays: map[string]Delay{"prepare": {Count: 1, MeanMs: 10}, "commit": {Count: 1, MeanMs: 20}}},
		{Validator: "a2", Heights: 3, ProposerRounds: 2, Proposed: 1, Missed: 1, Sealed: 3, Late: 1,
			Delays: map[string]Delay{"prepare": {Count: 2, MeanMs: 40}}},
	}
	if !reflect.DeepEqual(s.Validators, want) {
		t.Fatalf("validators\n got %+v\nwant %+v", s.Validators, want)
	}
	rc := RoundChanges(recs)
	wantRC := []RoundChange{{Height: "3", Round: "0", Proposer: "a1"},
		{Height: "4", Round: "0", Proposer: "a2", Cause: "timeout", Next: "2"},
		{Height: "4", Round: "1", Proposer: "a0", Cause: "timeout", Next: "2"}}
	if !reflect.DeepEqual(rc, wantRC) {
		t.Fatalf("round changes\n got %+v\nwant %+v", rc, wantRC)
	}
}
