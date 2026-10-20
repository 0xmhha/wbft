package consensus

import (
	"fmt"
	"testing"
)

func TestHigherRoundSendersFollowPair(t *testing.T) {
	prior := KnownImprovements() &^ ImprovementSet(0).With(FollowHigherRoundChanges)
	for _, n := range []int{4, 5, 6} {
		for _, base := range []ImprovementSet{0, RestartSafety, prior} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%d/%t", n, base, enabled), func(t *testing.T) {
					flags := base
					if enabled {
						flags = flags.With(FollowHigherRoundChanges)
					}
					h := newHarness(t, n, 1)
					h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: flags})
					h.start()
					// Each remote signer moves monotonically. No internal queue/state
					// setup or malformed message is needed to exceed the old window.
					h.deliver(0, h.roundChange(0, view(10, 2), nil, nil, nil))
					h.deliver(0, h.roundChange(0, view(10, 3), nil, nil, nil))
					h.deliver(2, h.roundChange(2, view(10, 3), nil, nil, nil))
					h.expect(Process, rowRCFPlusOne, true)
					h.wantView(10, 2, AcceptRequest)
					h.deliver(3, h.roundChange(3, view(10, 3), nil, nil, nil))
					if enabled {
						h.expect(Process, rowRCFPlusOne, true)
						h.wantView(10, 3, AcceptRequest)
						messages := h.broadcasts()
						if len(messages) != 1 || messages[0].Msg.View.Cmp(view(10, 3)) != 0 {
							t.Fatal("higher round was not followed", h.out)
						}
					} else {
						h.expect(Process, rowRCStored, true)
						h.wantView(10, 2, AcceptRequest)
						if len(h.broadcasts()) != 0 {
							t.Fatal("legacy round window changed")
						}
					}
				})
			}
		}
	}
}
