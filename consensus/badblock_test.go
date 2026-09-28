package consensus

import (
	"testing"

	"github.com/0xmhha/wbft/codec"
)

// withImprovements replaces the core of h with one that runs set.
func withImprovements(h *harness, set ImprovementSet) {
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: set})
}

// ownRoundChanges returns the ROUND-CHANGE broadcasts of the last step.
func ownRoundChanges(h *harness) []Broadcast {
	var out []Broadcast
	for _, b := range h.broadcasts() {
		if b.Msg.Code == codec.CodeRoundChange {
			out = append(out, b)
		}
	}
	return out
}

// A failed finalize sends ROUND-CHANGE (10, 1) with the prepared pair; the
// round timer then enters round 1, the bad-block rule releases the pair, and
// ROUND-CHANGE (10, 1) is sent again without it. Only the second one is
// marked, and only with BadBlockReleaseMark. The messages are the same with
// and without the mark.
func TestBadBlockReleaseMark(t *testing.T) {
	for _, tt := range []struct {
		name string
		set  ImprovementSet
		mark bool
	}{
		{"reference", 0, false},
		{"restart safety", RestartSafety, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, 4, 1)
			withImprovements(h, tt.set)
			h.env.finalizeFail = true
			h.start()
			b := h.proposal(1)
			h.reachCommitted(b)
			first := ownRoundChanges(h)
			if len(first) != 1 || first[0].Msg.View.Cmp(view(10, 1)) != 0 || first[0].Msg.PreparedRound == nil {
				t.Fatalf("after the failed finalize: %+v", first)
			}
			if first[0].BadBlockReleased {
				t.Error("ROUND-CHANGE with a prepared pair is marked")
			}
			h.env.bad[blockHash(b)] = true
			h.roundTimeout()
			second := ownRoundChanges(h)
			if len(second) != 1 || second[0].Msg.View.Cmp(view(10, 1)) != 0 || second[0].Msg.PreparedRound != nil || second[0].Msg.PreparedBlock != nil {
				t.Fatalf("after the round timeout: %+v", second)
			}
			if second[0].BadBlockReleased != tt.mark {
				t.Errorf("mark %v, want %v", second[0].BadBlockReleased, tt.mark)
			}
			// The mark stays for the later rounds of the sequence.
			h.roundTimeout()
			third := ownRoundChanges(h)
			if len(third) != 1 || third[0].Msg.View.Cmp(view(10, 2)) != 0 || third[0].BadBlockReleased != tt.mark {
				t.Fatalf("round 2: %+v", third)
			}
		})
	}
}

// Without a bad block a ROUND-CHANGE is never marked, with or without a
// prepared pair.
func TestBadBlockReleaseMarkOnlyAfterRelease(t *testing.T) {
	h := newHarness(t, 4, 1)
	withImprovements(h, RestartSafety)
	h.start()
	h.roundTimeout()
	if rc := ownRoundChanges(h); len(rc) != 1 || rc[0].BadBlockReleased {
		t.Fatalf("round change without a lock: %+v", rc)
	}
	p := newHarness(t, 4, 1)
	withImprovements(p, RestartSafety)
	p.start()
	p.reachPrepared(p.proposal(1))
	p.roundTimeout()
	if rc := ownRoundChanges(p); len(rc) != 1 || rc[0].Msg.PreparedRound == nil || rc[0].BadBlockReleased {
		t.Fatalf("round change with a lock: %+v", rc)
	}
}
