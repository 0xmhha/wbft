package consensus

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
)

func normalRetryHarness(t *testing.T, enabled, cancellation bool) *harness {
	t.Helper()
	h := newHarness(t, 4, 3)
	options := Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: RestartSafety}
	if cancellation {
		options.Improvements = options.Improvements.With(CancelStaleRetries)
	}
	if enabled {
		options.RoundChangeRetry = &RoundChangeRetryOptions{MaxIntervalMs: 8000}
	}
	h.s = NewState(options)
	h.start()
	return h
}

func normalRetryArm(t *testing.T, h *harness) ArmTimer {
	t.Helper()
	for _, arm := range outputsOf[ArmTimer](h.out) {
		if arm.Kind == RetryTimer {
			return arm
		}
	}
	t.Fatal("normal retry timer missing")
	return ArmTimer{}
}

// These cases inspect core input/output contracts. Actual clock scheduling,
// persisted signatures and local queue/write observations are separate layers.
func TestNormalRoundChangeRetrySchedulePair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, cancellation := range []bool{false, true} {
			t.Run(fmt.Sprintf("retry=%t/cancel=%t", enabled, cancellation), func(t *testing.T) {
				h := normalRetryHarness(t, enabled, cancellation)
				block := h.proposal(1)
				block.Header.ParentHash = codec.BlockHash(h.env.head.Header)
				h.reachPrepared(block)
				h.roundTimeout()
				initialBroadcasts := h.broadcasts()
				if len(initialBroadcasts) != 1 {
					t.Fatal("initial round-change missing", h.out)
				}
				first := initialBroadcasts[0]
				if first.Retry != nil || len(first.Msg.Prepares) != 3 || first.Msg.PreparedRound == nil {
					t.Fatal("initial prepared round-change contract", first)
				}
				original := h.encode(first.Msg)
				initial := normalRetryArm(t, h)
				if initial.Duration != 2*time.Second {
					t.Fatal("initial retry interval", initial)
				}
				if enabled && (initial.Retry == nil || !initial.Retry.Known || initial.Retry.Exponent != 0) {
					t.Fatal("initial retry declaration", initial)
				}
				for i, want := range []time.Duration{4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second} {
					expiry := queuedRetryExpiry(t, h)
					h.step(expiry)
					broadcasts := h.broadcasts()
					if len(broadcasts) != 1 || !bytes.Equal(original, h.encode(broadcasts[0].Msg)) {
						t.Fatal("normal retry changed prepared payload")
					}
					arm := normalRetryArm(t, h)
					if enabled {
						intent := broadcasts[0].Retry
						if arm.Duration != want || arm.Retry == nil || !arm.Retry.Known || arm.Retry.Exponent != uint64(i+1) || arm.Retry.Key != initial.Retry.Key {
							t.Fatal("current retry schedule", i, arm)
						}
						if intent == nil || intent.Generation != expiry.Gen || intent.View.Cmp(expiry.View) != 0 || intent.Key != arm.Retry.Key {
							t.Fatal("pre-arm retry identity", intent, expiry)
						}
					} else if arm.Duration != 2*time.Second || arm.Retry != nil || broadcasts[0].Retry != nil || h.vars().RoundChangeRetry != nil {
						t.Fatal("original disabled behavior changed")
					}
				}
			})
		}
	}
}

func TestNormalQueuedPastRetryPreservesCurrentBackoff(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		t.Run(fmt.Sprint(cancellation), func(t *testing.T) {
			h := normalRetryHarness(t, true, cancellation)
			h.roundTimeout()
			// The old callback is queued once, then the ordinary round
			// timeout advances the view before that callback is consumed.
			past := queuedRetryExpiry(t, h)
			h.roundTimeout()
			initial := normalRetryArm(t, h)
			if initial.Duration != 2*time.Second || initial.Retry == nil || initial.Retry.Exponent != 0 {
				t.Fatal("new full view did not reset spacing")
			}
			for range 2 {
				current := queuedRetryExpiry(t, h)
				h.step(current)
			}
			before := *h.vars().RoundChangeRetry
			h.step(past)
			if len(h.broadcasts()) != 0 {
				t.Fatal("past round broadcast a current retry")
			}
			after := h.vars().RoundChangeRetry
			if after == nil || after.View.Cmp(before.View) != 0 || after.Key != before.Key || after.Exponent != before.Exponent {
				t.Fatal("past expiry reset current backoff", before, after)
			}
			if cancellation {
				if len(h.out) != 0 {
					t.Fatal("existing cancellation behavior changed", h.out)
				}
			} else {
				arm := normalRetryArm(t, h)
				if arm.Duration != 8*time.Second || arm.Retry.Key != before.Key || arm.Retry.Exponent != 2 {
					t.Fatal("past expiry shortened current retry spacing", arm)
				}
			}
		})
	}
}
