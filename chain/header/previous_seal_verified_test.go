// SPDX-FileCopyrightText: 2026 The wbft authors
// SPDX-License-Identifier: LGPL-3.0-or-later

package header

import (
	"bytes"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func previousSealInputs(f previousSealRoundFixture, key int, prepared, committed []types.SealEntry, verify bool) (*types.Header, ProposalInputs) {
	n := f.parent.Number.AddUint64(1)
	skeleton := &types.Header{ParentHash: codec.BlockHash(f.parent), UncleHash: types.EmptyUncleHash, Number: n,
		Root: keccak.Sum256(n.Bytes()), GasLimit: f.parent.GasLimit, BaseFee: f.parent.BaseFee}
	return skeleton, ProposalInputs{Coinbase: f.b.acc[key].addr, Signer: keySigner{f.b.acc[key].key},
		ExtraPrepared: prepared, ExtraCommitted: committed, ParentGasTip: f.b.tip, VerifyMergedPrevSeals: verify}
}

func TestPreviousSealVerifiedNormalRoundPairs(t *testing.T) {
	f := normalPreviousSealRounds(t)
	vs := f.b.set(f.parent, nil)
	parentExtra, err := codec.DecodeConsensusExtra(f.parent)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(f.parent.Extra)
	validP := f.b.seals(f.parent, 1, types.PrepareSeal, []int{3})
	validC := f.b.seals(f.parent, 1, types.CommitSeal, []int{3})
	for _, item := range []struct {
		name                 string
		prepared, committed  []types.SealEntry
		wantP, wantC         byte
		fallbackP, fallbackC bool
		legacyEqual          bool
	}{
		{name: "no_extra", wantP: 0x07, wantC: 0x07, legacyEqual: true},
		{name: "valid_same_round", prepared: validP, committed: validC, wantP: 0x0f, wantC: 0x0f, legacyEqual: true},
		{name: "prepared_fallback_only", prepared: f.prepared0[3:], committed: validC, wantP: 0x07, wantC: 0x0f, fallbackP: true},
		{name: "committed_fallback_only", prepared: validP, committed: f.committed0, wantP: 0x0f, wantC: 0x07, fallbackC: true},
		{name: "both_fallback", prepared: f.prepared0[3:], committed: f.committed0, wantP: 0x07, wantC: 0x07, fallbackP: true, fallbackC: true},
		{name: "already_present", prepared: f.b.seals(f.parent, 1, types.PrepareSeal, []int{1}), committed: f.b.seals(f.parent, 1, types.CommitSeal, []int{1}), wantP: 0x07, wantC: 0x07, legacyEqual: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			skeleton, in := previousSealInputs(f, 2, item.prepared, item.committed, true)
			h, err := PrepareProposal(f.b.env(f.parent.Time), skeleton, in)
			if err != nil {
				t.Fatal("normal selected merge did not produce a proposal", err)
			}
			x, err := codec.DecodeConsensusExtra(h)
			if err != nil || x.PrevRound != 1 {
				t.Fatal("selected merge lost the actual parent round", err)
			}
			if !bytes.Equal(x.PrevPreparedSeal.Sealers, []byte{item.wantP}) || !bytes.Equal(x.PrevCommittedSeal.Sealers, []byte{item.wantC}) {
				t.Fatal("valid additions or independent fallbacks were lost")
			}
			if err := verifyPrevSeals(f.parent, vs, x); err != nil {
				t.Fatal("assembled previous seals fail the existing header rule", err)
			}
			if item.fallbackP && !bytes.Equal(x.PrevPreparedSeal.Signature, parentExtra.PreparedSeal.Signature) || item.fallbackC && !bytes.Equal(x.PrevCommittedSeal.Signature, parentExtra.CommittedSeal.Signature) {
				t.Fatal("fallback did not preserve the verified original")
			}
			if item.legacyEqual {
				legacy := f.b.propose(2, item.prepared, item.committed)
				if !bytes.Equal(legacy.Extra, h.Extra) {
					t.Fatal("already valid previous seals changed their encoding")
				}
			}
			if !bytes.Equal(f.parent.Extra, before) {
				t.Fatal("selected verification changed the parent")
			}
		})
	}
}

type previousSealNumberLookup struct {
	types.ChainReader
	calls int
}

func (c *previousSealNumberLookup) HeaderByNumber(n uint64) *types.Header {
	c.calls++
	return c.ChainReader.HeaderByNumber(n)
}

func TestPreviousSealVerifiedParentQuery(t *testing.T) {
	f := normalPreviousSealRounds(t)
	vs := f.b.set(f.parent, nil)
	for _, verify := range []bool{false, true} {
		env := f.b.env(f.parent.Time)
		chain := &previousSealNumberLookup{ChainReader: env.Chain}
		env.Chain = chain
		calls := 0
		env.ValidatorLookup = func(n types.Height, parent types.Hash, parents []*types.Header) (*validator.Set, error) {
			calls++
			if n.Cmp(f.parent.Number) != 0 || parent != f.parent.ParentHash || parents != nil {
				t.Fatal("previous sealing query used the child or its next committee")
			}
			return vs, nil
		}
		skeleton, in := previousSealInputs(f, 2, nil, nil, verify)
		if _, err := PrepareProposal(env, skeleton, in); err != nil {
			t.Fatal(err)
		}
		if verify && (calls != 1 || chain.calls != 0) || !verify && (calls != 0 || chain.calls != 1) {
			t.Fatal("selected parent binding or disabled lookup order changed", verify, calls, chain.calls)
		}
	}
}

func TestPreviousSealVerifiedUnavailableSet(t *testing.T) {
	f := normalPreviousSealRounds(t)
	unavailable := errors.New("ordinary historical lookup unavailable")
	for _, nilResult := range []bool{false, true} {
		env := f.b.env(f.parent.Time)
		env.ValidatorLookup = func(types.Height, types.Hash, []*types.Header) (*validator.Set, error) {
			if nilResult {
				return nil, nil
			}
			return nil, unavailable
		}
		skeleton, in := previousSealInputs(f, 2, nil, nil, true)
		h, err := PrepareProposal(env, skeleton, in)
		want := unavailable
		if nilResult {
			want = ErrMissingConfig
		}
		if h != nil || !errors.Is(err, want) {
			t.Fatal("unavailable historical set became an unchecked proposal", h, err)
		}
		in.VerifyMergedPrevSeals = false
		if _, err := PrepareProposal(env, skeleton, in); err != nil {
			t.Fatal("disabled mode gained a historical lookup dependency", err)
		}
	}
}

func TestPreviousSealVerifiedOriginalContext(t *testing.T) {
	f := normalPreviousSealRounds(t)
	vs := f.b.set(f.parent, nil)
	original, err := aggregateSeals(f.prepared0)
	if err != nil {
		t.Fatal(err)
	}
	// The original quorum is valid for its own round. Supplying that same
	// aggregate with a different requested round must not grant a fallback.
	if err := VerifyAggregatedSeal(vs, f.parent, 0, original, types.PrepareSeal); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]types.SealEntry{nil, f.b.seals(f.parent, 1, types.PrepareSeal, []int{3})} {
		if result, err := verifiedPreviousSeal(vs, f.parent, 1, original, extra, types.PrepareSeal); result != nil || !errors.Is(err, ErrInvalidSeal) {
			t.Fatal("a valid quorum from another context became an unchecked fallback", result, err)
		}
	}
}

func TestPreviousSealVerifiedOtherReservedOptions(t *testing.T) {
	f := normalPreviousSealRounds(t)
	for _, parentByHash := range []bool{false, true} {
		skeleton, in := previousSealInputs(f, 2, nil, nil, true)
		in.PrevSealByParentHash, in.Allow32ByteVanity = parentByHash, !parentByHash
		if h, err := PrepareProposal(f.b.env(f.parent.Time), skeleton, in); h != nil || !errors.Is(err, ErrUnsupportedOption) {
			t.Fatal("selected merge enabled another reserved option", h, err)
		}
	}
}

func TestPreviousSealVerifiedFirstHeight(t *testing.T) {
	b := newBuilder(t)
	f := previousSealRoundFixture{b: b, parent: b.head()}
	env := b.env(f.parent.Time)
	env.ValidatorLookup = func(types.Height, types.Hash, []*types.Header) (*validator.Set, error) {
		t.Fatal("first height queried a previous sealing set")
		return nil, nil
	}
	skeleton, in := previousSealInputs(f, 0, nil, nil, true)
	h, err := PrepareProposal(env, skeleton, in)
	if err != nil {
		t.Fatal("selected verification blocked the first ordinary proposal", err)
	}
	legacy := b.propose(0, nil, nil)
	if !bytes.Equal(h.Extra, legacy.Extra) {
		t.Fatal("first-height selected encoding changed")
	}
}

func normalPreviousSealEpochRounds(t *testing.T) previousSealRoundFixture {
	t.Helper()
	b := newBuilder(t)
	b.build(3)
	proposal := b.propose(3, nil, nil)
	sealing := b.set(proposal, nil)
	ei := &types.EpochInfo{}
	for _, account := range b.acc[:4] {
		ei.Candidates = append(ei.Candidates, types.Candidate{Addr: account.addr, Diligence: types.DefaultDiligence})
	}
	// A normal epoch declaration reorders the existing owned candidates.
	// The first three new positions differ from the parent's sealing quorum.
	for _, index := range []int{3, 1, 0, 2} {
		member := sealing.At(index)
		found := false
		for candidate, account := range b.acc[:4] {
			if account.addr == member.Addr {
				ei.Validators = append(ei.Validators, uint32(candidate))
				ei.BLSPublicKeys = append(ei.BLSPublicKeys, bytes.Clone(member.BLSPublicKey))
				found = true
				break
			}
		}
		if !found {
			t.Fatal("normal epoch candidate is not owned")
		}
	}
	b.setEpochInfo(proposal, ei)
	prepared0 := b.seals(proposal, 0, types.PrepareSeal, []int{0, 1, 2, 3})
	committed0 := b.seals(proposal, 0, types.CommitSeal, []int{3})
	parent := b.seal(proposal, 1, []int{0, 1, 2})
	if codec.BlockHash(parent) != codec.BlockHash(proposal) {
		t.Fatal("epoch commit changed the normal proposal identity")
	}
	b.store(parent)
	if err := VerifyHeader(b.env(parent.Time+100), parent, nil, headerOnly); err != nil {
		t.Fatal("normal epoch parent does not verify", err)
	}
	vs := b.set(parent, nil)
	quorum, err := aggregateSeals(prepared0)
	if err != nil || VerifyAggregatedSeal(vs, parent, 0, quorum, types.PrepareSeal) != nil {
		t.Fatal("normal epoch round-zero prepared quorum does not verify", err)
	}
	key, err := bls.DecodePublicKey(vs.At(3).BLSPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bls.DecodeSignature(committed0[0].Seal)
	if err != nil || !bls.Verify(key, codec.SealData(parent, 0, types.CommitSeal), sig) {
		t.Fatal("normal epoch commit has lost its original round", err)
	}
	return previousSealRoundFixture{b: b, parent: parent, prepared0: prepared0, committed0: committed0}
}

func TestPreviousSealVerifiedHistoricalEpochSet(t *testing.T) {
	f := normalPreviousSealEpochRounds(t)
	past := f.b.set(f.parent, nil)
	next, err := validator.ValidatorsAt(f.b.chain, f.b.cfg, f.parent.Number.AddUint64(1), codec.BlockHash(f.parent), nil)
	if err != nil {
		t.Fatal(err)
	}
	parentExtra, err := codec.DecodeConsensusExtra(f.parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAggregatedSeal(past, f.parent, 1, parentExtra.PreparedSeal, types.PrepareSeal); err != nil {
		t.Fatal("actual historical quorum does not verify", err)
	}
	if err := VerifyAggregatedSeal(next, f.parent, 1, parentExtra.PreparedSeal, types.PrepareSeal); !errors.Is(err, ErrInvalidSeal) {
		t.Fatal("normal epoch fixture does not distinguish the next committee", err)
	}
	for _, extra := range []bool{false, true} {
		var prepared, committed []types.SealEntry
		if extra {
			prepared, committed = f.prepared0[3:], f.committed0
		}
		skeleton, in := previousSealInputs(f, 3, prepared, committed, true)
		h, err := PrepareProposal(f.b.env(f.parent.Time), skeleton, in)
		if err != nil {
			t.Fatal("epoch proposal did not use the actual historical set", err)
		}
		x, err := codec.DecodeConsensusExtra(h)
		if err != nil || !bytes.Equal(x.PrevPreparedSeal.Sealers, []byte{0x07}) || !bytes.Equal(x.PrevCommittedSeal.Sealers, []byte{0x07}) {
			t.Fatal("epoch selection lost the verified original quorum", err)
		}
		if err := verifyPrevSeals(f.parent, past, x); err != nil {
			t.Fatal("epoch previous seals fail the original header check", err)
		}
	}
}
