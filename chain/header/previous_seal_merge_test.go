// SPDX-FileCopyrightText: 2026 The wbft authors
// SPDX-License-Identifier: LGPL-3.0-or-later

package header

import (
	"bytes"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

type previousSealRoundFixture struct {
	b                     *builder
	parent                *types.Header
	prepared0, committed0 []types.SealEntry
}

// All signatures use owned keys and their original block, round and seal type.
// A round-zero prepared quorum and one commit precede the round-one quorum.
// This is a header fixture, without network input or a transaction.
func normalPreviousSealRounds(t *testing.T) previousSealRoundFixture {
	t.Helper()
	b := newBuilder(t)
	b.build(1)
	proposal := b.propose(1, nil, nil)
	prepared0 := b.seals(proposal, 0, types.PrepareSeal, []int{0, 1, 2, 3})
	committed0 := b.seals(proposal, 0, types.CommitSeal, []int{3})
	parent := b.seal(proposal, 1, []int{0, 1, 2})
	if codec.BlockHash(parent) != codec.BlockHash(proposal) {
		t.Fatal("normal commit changed the proposal block identity")
	}
	b.store(parent)
	if err := VerifyHeader(b.env(parent.Time+100), parent, nil, headerOnly); err != nil {
		t.Fatal("normal round-one parent does not verify", err)
	}
	vs := b.set(parent, nil)
	prepared, err := aggregateSeals(prepared0)
	if err != nil || VerifyAggregatedSeal(vs, parent, 0, prepared, types.PrepareSeal) != nil {
		t.Fatal("normal round-zero prepared quorum is not valid", err)
	}
	committed, err := aggregateSeals(committed0)
	if err != nil || !errors.Is(VerifyAggregatedSeal(vs, parent, 0, committed, types.CommitSeal), ErrLackOfSealCount) {
		t.Fatal("round-zero commit unexpectedly has a quorum", err)
	}
	key, err := bls.DecodePublicKey(vs.At(3).BLSPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bls.DecodeSignature(committed0[0].Seal)
	if err != nil || !bls.Verify(key, codec.SealData(parent, 0, types.CommitSeal), sig) {
		t.Fatal("the ordinary single round-zero commit is not valid", err)
	}
	return previousSealRoundFixture{b: b, parent: parent, prepared0: prepared0, committed0: committed0}
}

// The disabled-mode baseline preserves the original aggregation behavior.
// A valid signature for a different round still aggregates mathematically;
// its result does not verify against the committed parent's actual round.
func TestPreviousSealMergeNormalRoundBaseline(t *testing.T) {
	f := normalPreviousSealRounds(t)
	vs := f.b.set(f.parent, nil)
	before := bytes.Clone(f.parent.Extra)
	for _, item := range []struct {
		name                string
		prepared, committed []types.SealEntry
		invalidP, invalidC  bool
	}{
		{name: "no_extra"},
		{name: "prepared_other_round", prepared: f.prepared0[3:], invalidP: true},
		{name: "committed_other_round", committed: f.committed0, invalidC: true},
		{name: "both_other_round", prepared: f.prepared0[3:], committed: f.committed0, invalidP: true, invalidC: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			child := f.b.propose(2, item.prepared, item.committed)
			x, err := codec.DecodeConsensusExtra(child)
			if err != nil || x.PrevRound != 1 {
				t.Fatal("normal child lost the committed parent round", err)
			}
			for _, check := range []struct {
				name    string
				seal    *types.AggregatedSeal
				kind    types.SealType
				invalid bool
			}{
				{name: "prepared", seal: x.PrevPreparedSeal, kind: types.PrepareSeal, invalid: item.invalidP},
				{name: "committed", seal: x.PrevCommittedSeal, kind: types.CommitSeal, invalid: item.invalidC},
			} {
				wantBitmap := byte(0x07)
				if check.invalid {
					wantBitmap = 0x0f
				}
				if !bytes.Equal(check.seal.Sealers, []byte{wantBitmap}) {
					t.Fatal("baseline did not select the expected distinct signer indices", check.name)
				}
				err := VerifyAggregatedSeal(vs, f.parent, x.PrevRound, check.seal, check.kind)
				if check.invalid && !errors.Is(err, ErrInvalidSeal) || !check.invalid && err != nil {
					t.Fatal("ordinary round aggregation baseline changed", check.name, err)
				}
			}
			if !bytes.Equal(f.parent.Extra, before) {
				t.Fatal("proposal construction changed its committed parent")
			}
			t.Logf("normal_previous_seal_baseline parent_round=1 prepared_invalid=%t committed_invalid=%t owned_round0_prepared=4 owned_round0_commits=1 committed_round1_quorum=3 network_packets=0 transactions=0", item.invalidP, item.invalidC)
		})
	}
}
