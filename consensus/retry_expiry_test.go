package consensus

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func queuedRetryExpiry(t *testing.T, h *harness) Timeout {
	t.Helper()
	for _, a := range outputsOf[ArmTimer](h.out) {
		if a.Kind == RetryTimer {
			return Timeout{Kind: a.Kind, View: a.View, Round: a.Round, Gen: a.Gen}
		}
	}
	t.Fatal("retry was not armed")
	return Timeout{}
}

func retryOptionHarness(t *testing.T, base ImprovementSet, enabled bool, self int) *harness {
	t.Helper()
	h := newHarness(t, 4, self)
	if enabled {
		base = base.With(CancelStaleRetries)
	}
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[self], Improvements: base})
	h.start()
	return h
}

func TestCancelledRetryAfterNewHeadPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(CancelStaleRetries)} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", base, enabled), func(t *testing.T) {
				h := retryOptionHarness(t, base, enabled, 1)
				b := h.proposal(1)
				b.Header.ParentHash = blockHash(h.env.head)
				committed := certifiedOrderBlock(t, h, b)
				h.reachPrepared(b)
				h.roundTimeout()
				expiry := queuedRetryExpiry(t, h)
				h.env.head = committed
				h.step(NewHead{Header: committed.Header})
				h.wantView(11, 0, AcceptRequest)
				h.step(expiry)
				if enabled {
					if len(h.out) != 0 {
						t.Fatal("cancelled prior-height expiry emitted output", h.out)
					}
				} else {
					bs := h.broadcasts()
					if len(bs) != 1 || bs[0].Msg.View.Cmp(view(11, 1)) != 0 {
						t.Fatal("legacy queued retry changed", h.out)
					}
				}
				h.wantView(11, 0, AcceptRequest)
			})
		}
	}
}

func TestCancelledRetryAfterValidProposalPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			h := retryOptionHarness(t, RestartSafety, enabled, 2)
			h.roundTimeout()
			expiry := queuedRetryExpiry(t, h)
			b := h.block(10, 1, h.addrs[1])
			b.Header.ParentHash = blockHash(h.env.head)
			rcs := []*codec.Message{}
			for _, i := range []int{0, 1, 3} {
				rcs = append(rcs, h.roundChange(i, view(10, 1), nil, nil, nil))
			}
			h.deliver(1, h.preprepare(1, view(10, 1), b, rcs, nil))
			h.expect(Process, rowPreprepareAccept, true)
			h.wantView(10, 1, Preprepared)
			h.step(expiry)
			if enabled {
				if len(h.out) != 0 {
					t.Fatal("same-view cancellation did not stop queued retry", h.out)
				}
			} else if len(h.broadcasts()) != 1 || len(outputsOf[ArmTimer](h.out)) != 1 {
				t.Fatal("legacy retry changed", h.out)
			}
			h.wantView(10, 1, Preprepared)
		})
	}
}

func TestCurrentAndPastRoundRetryPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			h := retryOptionHarness(t, RestartSafety, enabled, 2)
			h.roundTimeout()
			first := queuedRetryExpiry(t, h)
			h.step(first)
			current := queuedRetryExpiry(t, h)
			if len(h.broadcasts()) != 1 || h.broadcasts()[0].Msg.View.Cmp(view(10, 1)) != 0 || current.Gen <= first.Gen {
				t.Fatal("current retry did not send and rearm", h.out)
			}
			h.roundTimeout()
			h.wantView(10, 2, AcceptRequest)
			h.step(current)
			if len(h.broadcasts()) != 0 {
				t.Fatal("past round retry sent a message")
			}
			arms := outputsOf[ArmTimer](h.out)
			if enabled && len(h.out) != 0 {
				t.Fatal("superseded expiry rearmed", h.out)
			}
			if !enabled && (len(arms) != 1 || arms[0].Kind != RetryTimer || arms[0].Round.Cmp(types.RoundFromUint64(2)) != 0) {
				t.Fatal("legacy retry rearming changed", arms)
			}
		})
	}
}
