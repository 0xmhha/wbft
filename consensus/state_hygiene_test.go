package consensus

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// The application is a unit stub. Votes and certificates are normally signed;
// these controls do not establish execution-layer validity or network incidence.
func TestPreparedCertificateLifetimePair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, RestartSafety.With(CancelStaleRetries).With(FollowHigherRoundChanges)} {
		for _, action := range []string{"same_height", "queued_new_head", "local_release"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/%t", base, action, enabled), func(t *testing.T) {
					h := newHarness(t, 4, 1)
					flags := base
					if enabled {
						flags = flags.With(BindPreparedCertificate)
					}
					withImprovements(h, flags)
					h.start()
					b := h.proposal(1)
					b.Header.ParentHash = blockHash(h.env.head)
					certified := certifiedOrderBlock(t, h, b)
					h.reachPrepared(b)
					if len(h.vars().Certificate) != 3 {
						t.Fatal("normal prepared certificate missing")
					}
					switch action {
					case "queued_new_head":
						h.env.head = certified
					case "local_release":
						h.env.bad[blockHash(b)] = true
					}
					h.roundTimeout()
					v := h.vars()
					rcs := ownRoundChanges(h)
					want := 3
					if enabled && action != "same_height" {
						want = 0
					}
					if len(v.Certificate) != want || len(rcs) != 1 || len(rcs[0].Msg.Prepares) != want {
						t.Fatal("certificate lifetime", v, rcs)
					}
					if action == "same_height" {
						if v.LockedBlock == nil || v.LockedRound == nil || *v.LockedBlock != blockHash(b) {
							t.Fatal("ordinary round lost the pair")
						}
					} else if v.LockedBlock != nil || v.LockedRound != nil {
						t.Fatal("released pair retained")
					}
					if enabled && len(h.s.certificate) != 0 {
						t.Fatal("enabled policy used the legacy certificate store")
					}
				})
			}
		}
	}
}

func TestUnboundExtraSealRelayPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, RestartSafety.With(CancelStaleRetries).With(ScanReadyBacklog)} {
		for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
			for _, target := range []bool{false, true} {
				for _, enabled := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/%d/target%t/%t", base, code, target, enabled), func(t *testing.T) {
						h := newHarness(t, 4, 1)
						flags := base
						if enabled {
							flags = flags.With(DropUnboundExtraSeals)
						}
						withImprovements(h, flags)
						h.start()
						b := h.env.head
						seq := uint64(9)
						if target {
							b = h.proposal(1)
							b.Header.ParentHash = blockHash(h.env.head)
							certified := certifiedOrderBlock(t, h, b)
							h.reachCommitted(b)
							h.env.head = certified
							h.step(NewHead{})
							seq = 10
						}
						h.deliver(3, h.vote(3, code, view(seq, 0), b))
						row := rowExtraNoTarget
						if target {
							row = rowExtraStored
						}
						h.expect(ExtraSeal, row, target || !enabled)
						stored := h.vars().ExtraPrepareSeals
						if code == codec.CodeCommit {
							stored = h.vars().ExtraCommitSeals
						}
						if target && len(stored) == 0 || !target && len(stored) != 0 {
							t.Fatal("late vote storage", stored)
						}
					})
				}
			}
		}
	}
}

func TestDelayedRoundProposalPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(ResumeRoundProposals)} {
		for _, mode := range []string{"delayed", "insufficient", "nonproposer", "prepared_priority"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/%t", base, mode, enabled), func(t *testing.T) {
					self := 1
					if mode == "nonproposer" {
						self = 3
					}
					h := newHarness(t, 4, self)
					flags := base
					if enabled {
						flags = flags.With(ResumeRoundProposals)
					}
					withImprovements(h, flags)
					h.start()
					h.roundTimeout()
					b := h.proposal(1)
					b.Header.ParentHash = blockHash(h.env.head)
					if mode != "prepared_priority" {
						// A fresh round-1 builder block belongs to its current proposer.
						b.Header.Coinbase = h.addrs[1]
					}
					var ps []*codec.Message
					if mode == "prepared_priority" {
						for _, i := range []int{0, 1, 2} {
							ps = append(ps, h.prepare(i, view(10, 0), b))
						}
					}
					limit := 3
					if mode == "insufficient" {
						limit = 2
					}
					for i := 0; i < limit; i++ {
						var round *types.Round
						var block *types.Block
						var prepares []*codec.Message
						if mode == "prepared_priority" && i == 0 {
							round = roundPtr(0)
							block = b
							prepares = ps
						}
						h.deliver(i, h.roundChange(i, view(10, 1), round, block, prepares))
					}
					if mode == "delayed" {
						h.expect(Process, rowRCNoProposal, enabled)
					}
					if mode == "prepared_priority" {
						bs := h.broadcasts()
						if len(bs) != 1 || blockHash(bs[0].Msg.Proposal) != blockHash(b) || len(bs[0].Msg.Prepares) != 3 {
							t.Fatal("highest prepared proposal not preferred", bs)
						}
					}
					h.step(Request{Block: b})
					bs := h.broadcasts()
					want := enabled && mode == "delayed"
					if (len(bs) == 1) != want || len(bs) > 1 {
						t.Fatal("delayed request proposal", mode, enabled, bs)
					}
					if want {
						if bs[0].Msg.Code != codec.CodePreprepare || len(bs[0].Msg.RoundChanges) != 3 || blockHash(bs[0].Msg.Proposal) != blockHash(b) {
							t.Fatal("justification or proposal changed", bs)
						}
					}
					if enabled && mode != "insufficient" && mode != "nonproposer" {
						h.step(Request{Block: b})
						if len(h.broadcasts()) != 0 {
							t.Fatal("same round proposed twice")
						}
					}
				})
			}
		}
	}
}
