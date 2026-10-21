package consensus

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// All messages and prepared certificates are normally signed and parent-linked.
// A local application callback models a normal clock skew, without changing packets.
func TestFutureProposalWaitReceivedPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(LimitFutureProposalWait)} {
		for _, wait := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%d/%t", base, wait, enabled), func(t *testing.T) {
					h := newHarness(t, 4, 1)
					flags := base
					if enabled {
						flags = flags.With(LimitFutureProposalWait)
					}
					withImprovements(h, flags)
					h.start()
					b := h.proposal(1)
					b.Header.ParentHash = blockHash(h.env.head)
					h.env.future[blockHash(b)] = wait
					generation := h.s.gen[FutureTimer]
					h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
					blocked := enabled && wait > 2*time.Second
					arms := outputsOf[ArmTimer](h.out)
					if blocked {
						h.expect(Process, rowPreprepareReject, false)
						if len(arms) != 0 || h.s.gen[FutureTimer] != generation || h.s.futureLive {
							t.Fatal("rejected future proposal changed wait state", arms)
						}
					} else {
						h.expect(Process, rowPreprepareFuture, false)
						if len(arms) != 1 || arms[0].Kind != FutureTimer || arms[0].Duration != wait || arms[0].Msg == nil {
							t.Fatal("allowed received wait lost provenance", arms)
						}
					}
					assertFutureWaitHealth(t, h, blocked, "preprepare", wait, 2*time.Second)
				})
			}
		}
	}
}

func TestFutureProposalWaitLocalPair(t *testing.T) {
	for _, wait := range []time.Duration{3 * time.Second, 4 * time.Second, 5 * time.Second} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", wait, enabled), func(t *testing.T) {
				h := newHarness(t, 4, 1)
				flags := RestartSafety.With(ValidateRoundProposals)
				if enabled {
					flags = flags.With(LimitFutureProposalWait)
				}
				withImprovements(h, flags)
				h.start()
				h.roundTimeout()
				b := h.proposal(1)
				b.Header.ParentHash = blockHash(h.env.head)
				h.env.future[blockHash(b)] = wait
				ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(2, view(10, 0), b), h.prepare(3, view(10, 0), b)}
				for _, source := range []int{0, 2, 3} {
					h.deliver(source, h.roundChange(source, view(10, 1), roundPtr(0), b, ps))
				}
				blocked := enabled && wait > 4*time.Second
				arms := outputsOf[ArmTimer](h.out)
				if len(h.broadcasts()) != 0 || h.env.validateCalls != 1 {
					t.Fatal("local candidate bypassed validation", h.env.validateCalls)
				}
				if blocked {
					if len(arms) != 0 || h.s.roundProposalLive {
						t.Fatal("local rejection armed a wait", arms)
					}
				} else {
					if len(arms) != 1 || arms[0].Kind != RoundProposalTimer || arms[0].Msg != nil || arms[0].Duration != wait {
						t.Fatal("allowed local wait claimed a received message", arms)
					}
				}
				assertFutureWaitHealth(t, h, blocked, "local_reproposal", wait, 4*time.Second)
			})
		}
	}
}

func TestFutureProposalWaitUsesSelectedInitialCap(t *testing.T) {
	for _, capped := range []bool{false, true} {
		for _, limited := range []bool{false, true} {
			t.Run(fmt.Sprintf("cap=%t/limit=%t", capped, limited), func(t *testing.T) {
				h := newHarness(t, 4, 1)
				policy, cap := uint64(0), uint64(1)
				h.cfg = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: &cap}, nil, types.GenesisInit{}, nil)
				flags := RestartSafety
				if capped {
					flags = flags.With(CapInitialRoundTimeout)
				}
				if limited {
					flags = flags.With(LimitFutureProposalWait)
				}
				withImprovements(h, flags)
				h.start()
				before := h.s.gen
				b := h.proposal(1)
				b.Header.ParentHash = blockHash(h.env.head)
				wait := 1500 * time.Millisecond
				h.env.future[blockHash(b)] = wait
				h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
				blocked := capped && limited
				arms := outputsOf[ArmTimer](h.out)
				if blocked {
					if len(arms) != 0 || h.s.gen != before || !h.s.roundLive {
						t.Fatal("limit rejection changed existing round timer state", h.s.gen, before)
					}
				} else if len(arms) != 1 || arms[0].Kind != FutureTimer || arms[0].Duration != wait {
					t.Fatal("independent options changed an allowed wait", arms)
				}
				limit := 2 * time.Second
				if capped {
					limit = time.Second
				}
				assertFutureWaitHealth(t, h, blocked, "preprepare", wait, limit)
			})
		}
	}
}

func assertFutureWaitHealth(t *testing.T, h *harness, want bool, origin string, wait, limit time.Duration) {
	t.Helper()
	found := 0
	for _, e := range outputsOf[Event](h.out) {
		if e.Record.Kind == event.Health && e.Record.Fields["what"] == "future_proposal_wait_exceeded" {
			found++
			f := e.Record.Fields
			if f["proposal_origin"] != origin || f["wait_ns"] != fmt.Sprint(int64(wait)) || f["limit_ns"] != fmt.Sprint(int64(limit)) || e.Record.View == nil || e.Record.View.Seq != "10" {
				t.Fatal("closed wait rejection metadata", e.Record)
			}
		}
	}
	if (found == 1) != want || found > 1 {
		t.Fatal("unexpected wait rejection observations", found, want)
	}
}
