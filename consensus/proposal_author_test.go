package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestProposalAuthorNormalPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			flags := RestartSafety
			if enabled {
				flags = flags.With(BindFreshProposalAuthor)
			}
			// The ordinary initial proposer builds and receives its own proposal.
			initial := newHarness(t, 4, 0)
			withImprovements(initial, flags)
			initial.start()
			b := initial.proposal(1)
			initial.step(Request{Block: b})
			sent := initial.broadcasts()
			if len(sent) != 1 || sent[0].Msg.Code != codec.CodePreprepare {
				t.Fatal("initial proposal not sent", sent)
			}
			initial.selfDeliver(sent[0])
			initial.expect(Process, rowPreprepareAccept, true)
			initial.wantView(10, 0, Preprepared)

			// A later round with no prepared pair creates a fresh block of its proposer.
			fresh := newHarness(t, 4, 1)
			withImprovements(fresh, flags)
			fresh.start()
			fresh.roundTimeout()
			candidate := fresh.block(10, 2, fresh.addrs[1])
			fresh.step(Request{Block: candidate})
			for _, i := range []int{0, 2, 3} {
				fresh.deliver(i, fresh.roundChange(i, view(10, 1), nil, nil, nil))
			}
			sent = fresh.broadcasts()
			if len(sent) != 1 || sent[0].Msg.Code != codec.CodePreprepare {
				t.Fatal("fresh later proposal not sent", sent)
			}
			fresh.selfDeliver(sent[0])
			fresh.expect(Process, rowPreprepareAccept, true)
			fresh.wantView(10, 1, Preprepared)
			if blockHash(fresh.s.cur.preprepare.Msg.Proposal) != blockHash(candidate) {
				t.Fatal("fresh proposal changed")
			}

			// A prepared block retains its original author when a later proposer sends it.
			prepared := newHarness(t, 4, 1)
			withImprovements(prepared, flags)
			prepared.start()
			prepared.roundTimeout()
			original := prepared.proposal(3)
			hash := blockHash(original)
			ps := []*codec.Message{prepared.prepare(0, view(10, 0), original), prepared.prepare(2, view(10, 0), original), prepared.prepare(3, view(10, 0), original)}
			for _, i := range []int{0, 2, 3} {
				prepared.deliver(i, prepared.roundChange(i, view(10, 1), roundPtr(0), original, ps))
			}
			sent = prepared.broadcasts()
			if len(sent) != 1 || sent[0].Msg.Code != codec.CodePreprepare || len(sent[0].Msg.Prepares) != 3 {
				t.Fatal("prepared proposal not sent", sent)
			}
			prepared.selfDeliver(sent[0])
			prepared.expect(Process, rowPreprepareAccept, true)
			prepared.wantView(10, 1, Preprepared)
			accepted := prepared.s.cur.preprepare.Msg.Proposal
			if blockHash(accepted) != hash || accepted.Header.Coinbase != prepared.addrs[0] || accepted.Header.Coinbase == prepared.addrs[1] {
				t.Fatal("prepared block author or hash changed")
			}
			prepared.roundTimeout()
			var rcs []*codec.Message
			for _, i := range []int{0, 2, 3} {
				rc := prepared.roundChange(i, view(10, 2), roundPtr(0), original, ps)
				rcs = append(rcs, rc)
				prepared.deliver(i, rc)
			}
			prepared.deliver(2, prepared.preprepare(2, view(10, 2), original, rcs, ps))
			prepared.expect(Process, rowPreprepareAccept, true)
			prepared.wantView(10, 2, Preprepared)
			if blockHash(prepared.s.cur.preprepare.Msg.Proposal) != hash || prepared.s.cur.preprepare.Msg.Proposal.Header.Coinbase != prepared.addrs[0] {
				t.Fatal("second reproposal changed the original author or block")
			}
		})
	}
}

// These are pure metadata inputs, not signed frames sent to a running node.
// Signature recovery and membership are prerequisites of the production caller.
func TestProposalAuthorCertificateContext(t *testing.T) {
	number := types.MustHeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(10)))
	target := types.View{Sequence: number, Round: types.RoundFromUint64(2)}
	author, sender := types.Address{1}, types.Address{2}
	block := &types.Block{Header: &types.Header{Number: number, Coinbase: author}}
	if !proposalAuthorAllowed(author, target, block, nil, 3) || proposalAuthorAllowed(sender, target, block, nil, 3) {
		t.Fatal("fresh author identity")
	}
	certificate := func() []*Verified {
		ps := make([]*Verified, 3)
		for i := range ps {
			ps[i] = &Verified{Source: types.Address{byte(i + 1)}, Msg: &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: number, Round: types.RoundFromUint64(1)}, Digest: blockHash(block)}}
		}
		return ps
	}
	if !proposalAuthorAllowed(sender, target, block, certificate(), 3) {
		t.Fatal("ordinary prior-round certificate")
	}
	cases := map[string]func([]*Verified) []*Verified{
		"below-quorum":    func(ps []*Verified) []*Verified { return ps[:2] },
		"same-source":     func(ps []*Verified) []*Verified { ps[2].Source = ps[0].Source; return ps },
		"other-sequence":  func(ps []*Verified) []*Verified { ps[0].Msg.View.Sequence = types.HeightFromUint64(10); return ps },
		"current-round":   func(ps []*Verified) []*Verified { ps[0].Msg.View.Round = target.Round; return ps },
		"mixed-rounds":    func(ps []*Verified) []*Verified { ps[0].Msg.View.Round = types.Round{}; return ps },
		"other-digest":    func(ps []*Verified) []*Verified { ps[0].Msg.Digest = types.Hash{}; return ps },
		"other-phase":     func(ps []*Verified) []*Verified { ps[0].Msg.Code = codec.CodeCommit; return ps },
		"missing-member":  func(ps []*Verified) []*Verified { ps[0] = nil; return ps },
		"missing-message": func(ps []*Verified) []*Verified { ps[0].Msg = nil; return ps },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if proposalAuthorAllowed(sender, target, block, change(certificate()), 3) {
				t.Fatal("invalid certificate context accepted")
			}
		})
	}
	if proposalAuthorAllowed(sender, types.View{Sequence: number}, block, certificate(), 3) || proposalAuthorAllowed(sender, target, block, certificate(), 0) || proposalAuthorAllowed(sender, target, nil, nil, 3) {
		t.Fatal("missing target context accepted")
	}
	if proposalAuthorAllowed(author, view(10, 2), block, nil, 3) {
		t.Fatal("full sequence truncated")
	}
}
