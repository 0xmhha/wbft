package consensus

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// The signed messages and certificates are ordinary inputs. Validation
// failures and clock waits are local application test-double answers.
func roundProposalCandidate(t *testing.T, flags ImprovementSet, verdict string) (*harness, *types.Block) {
	t.Helper()
	h := newHarness(t, 4, 1)
	withImprovements(h, flags)
	h.start()
	h.roundTimeout()
	b := h.proposal(1)
	b.Header.ParentHash = blockHash(h.env.head)
	switch verdict {
	case "reject":
		h.env.invalid[blockHash(b)] = true
	case "future":
		h.env.future[blockHash(b)] = 7 * time.Millisecond
	}
	ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(2, view(10, 0), b), h.prepare(3, view(10, 0), b)}
	for _, source := range []int{0, 2, 3} {
		h.deliver(source, h.roundChange(source, view(10, 1), roundPtr(0), b, ps))
	}
	return h, b
}

func TestRoundProposalValidationPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(ValidateRoundProposals)} {
		for _, verdict := range []string{"accept", "reject", "future"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/%t", base, verdict, enabled), func(t *testing.T) {
					flags := base
					if enabled {
						flags = flags.With(ValidateRoundProposals)
					}
					h, b := roundProposalCandidate(t, flags, verdict)
					calls := 0
					if enabled {
						calls = 1
					}
					if h.env.validateCalls != calls {
						t.Fatal("local validation call count", h.env.validateCalls, calls)
					}
					wantProposal := !enabled || verdict == "accept"
					if (len(h.broadcasts()) == 1) != wantProposal {
						t.Fatal("proposal bypassed the selected validation behavior", h.broadcasts())
					}
					if wantProposal {
						if blockHash(h.broadcasts()[0].Msg.Proposal) != blockHash(b) {
							t.Fatal("prepared candidate was replaced")
						}
						return
					}
					arms := outputsOf[ArmTimer](h.out)
					if verdict == "reject" {
						if len(arms) != 0 {
							t.Fatal("a permanent local rejection armed a future wait")
						}
						return
					}
					if len(arms) != 1 || arms[0].Kind != RoundProposalTimer || arms[0].Msg != nil || arms[0].View.Cmp(view(10, 1)) != 0 || arms[0].Digest != blockHash(b) || arms[0].Duration != 7*time.Millisecond {
						t.Fatal("local wait claimed a received message or lost its context", arms)
					}
					arm := arms[0]
					ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(2, view(10, 0), b), h.prepare(3, view(10, 0), b)}
					h.deliver(0, h.roundChange(0, view(10, 1), roundPtr(0), b, ps))
					if h.env.validateCalls != 1 || len(outputsOf[ArmTimer](h.out)) != 0 || len(h.broadcasts()) != 0 {
						t.Fatal("an ordinary duplicate extended the local wait")
					}
					delete(h.env.future, blockHash(b))
					expiry := Timeout{Kind: arm.Kind, View: arm.View, Round: arm.Round, Gen: arm.Gen}
					h.step(expiry)
					if h.env.validateCalls != 2 || len(h.broadcasts()) != 1 || blockHash(h.broadcasts()[0].Msg.Proposal) != blockHash(b) {
						t.Fatal("the normal timestamp wait did not revalidate and propose")
					}
					h.step(expiry)
					if h.env.validateCalls != 2 || len(h.broadcasts()) != 0 {
						t.Fatal("a consumed expiry caused another proposal")
					}
				})
			}
		}
	}
}

func TestRoundProposalWaitOldView(t *testing.T) {
	h, b := roundProposalCandidate(t, RestartSafety.With(ValidateRoundProposals), "future")
	arm := outputsOf[ArmTimer](h.out)[0]
	h.roundTimeout()
	delete(h.env.future, blockHash(b))
	calls := h.env.validateCalls
	h.step(Timeout{Kind: arm.Kind, View: arm.View, Round: arm.Round, Gen: arm.Gen})
	if h.env.validateCalls != calls || len(h.broadcasts()) != 0 || h.s.roundProposalLive {
		t.Fatal("an old queued expiry survived a full-view transition")
	}
}

func TestRoundProposalAndReceivedFutureAreIndependent(t *testing.T) {
	h := newHarness(t, 4, 1)
	withImprovements(h, RestartSafety.With(ValidateRoundProposals))
	h.start()
	b := h.proposal(1)
	b.Header.ParentHash = blockHash(h.env.head)
	h.env.future[blockHash(b)] = time.Millisecond
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	received := outputsOf[ArmTimer](h.out)[0]
	if received.Kind != FutureTimer || received.Msg == nil {
		t.Fatal("normal received future proposal was not deferred")
	}
	h.roundTimeout()
	ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(2, view(10, 0), b), h.prepare(3, view(10, 0), b)}
	for _, source := range []int{0, 2, 3} {
		h.deliver(source, h.roundChange(source, view(10, 1), roundPtr(0), b, ps))
	}
	local := outputsOf[ArmTimer](h.out)[0]
	if local.Kind != RoundProposalTimer || local.Msg != nil {
		t.Fatal("local future candidate reused the received timer")
	}
	// The received expiry was already queued before the round transition.
	h.step(Timeout{Kind: received.Kind, View: received.View, Round: received.Round, Gen: received.Gen, Msg: received.Msg})
	queued := outputsOf[Schedule](h.out)
	if len(queued) != 1 || queued[0].In.(Replay).Msg != received.Msg || !h.s.roundProposalLive || h.s.gen[RoundProposalTimer] != local.Gen {
		t.Fatal("reference queued-message replay consumed the local wait")
	}
}

func TestRoundProposalTimerCheckpoint(t *testing.T) {
	h, _ := roundProposalCandidate(t, RestartSafety.With(ValidateRoundProposals), "future")
	gens := h.s.TimerGenerations()
	if len(gens) != 4 || gens[RoundProposalTimer] == 0 {
		t.Fatal("local timer generation missing", gens)
	}
	restored := NewState(h.s.Options())
	if err := restored.RestoreTimerGenerations(gens); err != nil {
		t.Fatal(err)
	}
	if restored.gen[RoundProposalTimer] != h.s.gen[RoundProposalTimer] || restored.TimerGens() != h.s.TimerGens() {
		t.Fatal("checkpoint lost a generation")
	}
	legacy := NewState(Options{Improvements: RestartSafety})
	if len(legacy.TimerGenerations()) != 3 {
		t.Fatal("default checkpoint acquired a local timer")
	}
	old := h.s.TimerGens()
	if err := restored.RestoreTimerGenerations(old[:]); err != nil || restored.gen[RoundProposalTimer] != 0 {
		t.Fatal("normal reference checkpoint could not be restored", err)
	}
}
