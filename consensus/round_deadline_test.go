package consensus

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
)

// Parent-linked proposals and round-change certificates are normally signed.
// The test observes acceptance outputs without changing any packet semantics.
func TestAcceptedProposalRoundDeadlinePair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(PreserveRoundDeadline)} {
		for _, round := range []uint64{0, 1} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%d/%t", base, round, enabled), func(t *testing.T) {
					h := newHarness(t, 4, 2)
					flags := base
					if enabled {
						flags = flags.With(PreserveRoundDeadline)
					}
					withImprovements(h, flags)
					h.start()
					var rcs []*codec.Message
					if round == 1 {
						h.roundTimeout()
						for _, source := range []int{0, 1, 3} {
							rc := h.roundChange(source, view(10, 1), nil, nil, nil)
							rcs = append(rcs, rc)
							h.deliver(source, rc)
						}
					}
					before := h.s.gen[RoundTimer]
					b := h.proposal(1)
					b.Header.ParentHash = blockHash(h.env.head)
					b.Header.Coinbase = h.addrs[int(round)]
					h.deliver(int(round), h.preprepare(int(round), view(10, round), b, rcs, nil))
					h.expect(Process, rowPreprepareAccept, true)
					if h.s.state != Preprepared || !h.s.roundLive || h.s.cur.view.Cmp(view(10, round)) != 0 {
						t.Fatal("normal proposal was not accepted")
					}
					roundArms := 0
					for _, a := range outputsOf[ArmTimer](h.out) {
						if a.Kind == RoundTimer {
							roundArms++
						}
					}
					wantArms, wantGen := 1, before+1
					if enabled {
						wantArms, wantGen = 0, before
					}
					if roundArms != wantArms || h.s.gen[RoundTimer] != wantGen {
						t.Fatal("round reservation changed", roundArms, h.s.gen[RoundTimer])
					}
					cancels := outputsOf[CancelTimers](h.out)
					if len(cancels) != 1 {
						t.Fatal("missing proposal timer cleanup", cancels)
					}
					for _, kind := range cancels[0].Kinds {
						if enabled && kind == RoundTimer {
							t.Fatal("existing round deadline cancelled")
						}
					}
					if len(cancels[0].Kinds) != len(TimerKinds(flags))-1+wantArms || h.s.retryLive || h.s.futureLive || h.s.future != nil || h.s.roundProposalLive {
						t.Fatal("other timer cleanup lost")
					}
				})
			}
		}
	}
}
