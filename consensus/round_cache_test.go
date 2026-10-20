package consensus

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
)

// The application is a unit stub. A local finalize failure followed by release
// produces both replacement messages; this is not a network-incidence test.
func TestRoundCertificateReplacementPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(RefreshRoundCertificates)} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", base, enabled), func(t *testing.T) {
				p := newHarness(t, 4, 2)
				withImprovements(p, RestartSafety.With(BindPreparedCertificate))
				p.env.finalizeFail = true
				p.start()
				b := p.proposal(1)
				b.Header.ParentHash = blockHash(p.env.head)
				p.deliver(0, p.preprepare(0, view(10, 0), b, nil, nil))
				p.selfDeliver(p.broadcasts()[0])
				p.deliver(0, p.prepare(0, view(10, 0), b))
				p.deliver(1, p.prepare(1, view(10, 0), b))
				p.wantView(10, 0, Prepared)
				p.selfDeliver(p.broadcasts()[0])
				p.deliver(0, p.commit(0, view(10, 0), b))
				p.deliver(1, p.commit(1, view(10, 0), b))
				first := ownRoundChanges(p)
				if len(first) != 1 || first[0].Msg.PreparedRound == nil || len(first[0].Msg.Prepares) != 3 {
					t.Fatal("local finalize failure did not retain the certificate", first)
				}
				p.env.bad[blockHash(b)] = true
				p.roundTimeout()
				second := ownRoundChanges(p)
				if len(second) != 1 || second[0].Msg.PreparedRound != nil || len(second[0].Msg.Prepares) != 0 || !second[0].BadBlockReleased || first[0].Msg.View.Cmp(second[0].Msg.View) != 0 {
					t.Fatal("local release did not replace the same target", second)
				}

				h := newHarness(t, 4, 1)
				flags := base
				if enabled {
					flags = flags.With(RefreshRoundCertificates)
				}
				withImprovements(h, flags)
				h.start()
				h.roundTimeout()
				candidate := h.block(10, 2, h.addrs[1])
				candidate.Header.ParentHash = blockHash(h.env.head)
				h.step(Request{Block: candidate})
				h.deliver(2, p.signed(2, first[0].Msg, nil))
				h.deliver(2, p.signed(2, second[0].Msg, nil))
				h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
				h.deliver(3, h.roundChange(3, view(10, 1), nil, nil, nil))
				row := rowRCNotJustified
				if enabled {
					row = rowRCProposed
				}
				h.expect(Process, row, true)
				e := h.s.rcs.rounds[1]
				if len(e.msgs) != 3 || (e.highestRound == nil) != enabled || (e.highestBlock == nil) != enabled || (len(e.highestJust) == 0) != enabled {
					t.Fatal("replaced certificate selection", e)
				}
				bs := h.broadcasts()
				if enabled {
					if len(bs) != 1 || blockHash(bs[0].Msg.Proposal) != blockHash(candidate) || len(bs[0].Msg.Prepares) != 0 || len(bs[0].Msg.RoundChanges) != 3 {
						t.Fatal("current unprepared quorum did not justify the builder block", bs)
					}
				} else if len(bs) != 0 {
					t.Fatal("legacy stale certificate unexpectedly proposed", bs)
				}
			})
		}
	}
}

// Both certificates cover the same block and round with valid quorum votes.
// Only their signer subsets and the order of two ordinary senders differ.
func TestRoundCertificateEqualRoundOrderPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, order := range [][]int{{0, 2}, {2, 0}} {
			t.Run(fmt.Sprintf("%t/%v", enabled, order), func(t *testing.T) {
				h := newHarness(t, 4, 3)
				flags := RestartSafety
				if enabled {
					flags = flags.With(RefreshRoundCertificates)
				}
				withImprovements(h, flags)
				h.start()
				h.roundTimeout()
				b := h.proposal(1)
				b.Header.ParentHash = blockHash(h.env.head)
				certs := map[int][]*codec.Message{
					0: {h.prepare(0, view(10, 0), b), h.prepare(1, view(10, 0), b), h.prepare(2, view(10, 0), b)},
					2: {h.prepare(0, view(10, 0), b), h.prepare(1, view(10, 0), b), h.prepare(3, view(10, 0), b)},
				}
				for _, source := range order {
					h.deliver(source, h.roundChange(source, view(10, 1), roundPtr(0), b, certs[source]))
					h.expect(Process, rowRCStored, true)
				}
				want := order[0]
				if enabled {
					want = 0
					if bytes.Compare(h.addrs[2][:], h.addrs[0][:]) < 0 {
						want = 2
					}
				}
				e := h.s.rcs.rounds[1]
				if e.highestRound == nil || !e.highestRound.IsZero() || e.highestBlock == nil || blockHash(e.highestBlock) != blockHash(b) || len(e.highestJust) != 3 {
					t.Fatal("valid equal-round certificate missing", e)
				}
				for i, vote := range e.highestJust {
					if !bytes.Equal(h.encode(vote.Msg), h.encode(certs[want][i])) {
						t.Fatal("equal-round certificate depends on the wrong sender", want, i)
					}
				}
			})
		}
	}
}

func TestCurrentExtraSealReleasePair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, KnownImprovements() &^ ImprovementSet(0).With(ClearCurrentExtraSeals)} {
		for _, release := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/release%t/%t", base, release, enabled), func(t *testing.T) {
					h := newHarness(t, 4, 2)
					flags := base
					if enabled {
						flags = flags.With(ClearCurrentExtraSeals)
					}
					withImprovements(h, flags)
					h.env.head = h.block(8, 0, h.addrs[3])
					h.start()
					b9 := h.block(9, 1, h.addrs[0])
					b9.Header.ParentHash = blockHash(h.env.head)
					h.deliver(0, h.preprepare(0, view(9, 0), b9, nil, nil))
					h.expect(Process, rowPreprepareAccept, true)
					h.env.head = certifiedOrderBlock(t, h, b9)
					h.step(NewHead{})
					for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
						h.deliver(0, h.vote(0, code, view(9, 0), b9))
						h.expect(ExtraSeal, rowExtraStored, true)
					}
					b10 := h.block(10, 2, h.addrs[1])
					b10.Header.ParentHash = blockHash(h.env.head)
					h.deliver(1, h.preprepare(1, view(10, 0), b10, nil, nil))
					h.selfDeliver(h.broadcasts()[0])
					h.deliver(0, h.prepare(0, view(10, 0), b10))
					h.deliver(1, h.prepare(1, view(10, 0), b10))
					h.wantView(10, 0, Prepared)
					h.selfDeliver(h.broadcasts()[0])
					h.deliver(0, h.commit(0, view(10, 0), b10))
					h.deliver(1, h.commit(1, view(10, 0), b10))
					h.wantView(10, 0, Committed)
					for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
						h.deliver(3, h.vote(3, code, view(10, 0), b10))
						h.expect(ExtraSeal, rowExtraStored, true)
					}
					h.env.bad[blockHash(b10)] = release
					h.roundTimeout()
					want := 2
					if release {
						want = 0
						if enabled {
							want = 1
						}
					}
					if len(h.s.extraPrepare) != want || len(h.s.extraCommit) != want {
						t.Fatal("release scope", h.vars())
					}
					if release && enabled && (h.s.extraPrepare[h.addrs[0]].Msg.View.Sequence.CmpUint64(9) != 0 || h.s.extraCommit[h.addrs[0]].Msg.View.Sequence.CmpUint64(9) != 0) {
						t.Fatal("surviving prior votes were not retained")
					}
				})
			}
		}
	}
}
