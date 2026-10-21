package header

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/types"
)

type futureTimeOrderedSteps struct{ seen []string }

func (p *futureTimeOrderedSteps) VerifyPartB(step string, _, _ *types.Header, _ types.BodyRaw) error {
	p.seen = append(p.seen, step)
	return nil
}

func futureTimeBuilder(t *testing.T, base, transition uint64) *builder {
	t.Helper()
	b := newBuilder(t)
	policy := uint64(0)
	var ts []types.Transition
	if transition > 0 {
		ts = []types.Transition{{Block: big.NewInt(1), WBFT: &types.WBFTParams{AllowedFutureBlockTime: transition}}}
	}
	b.cfg = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: &policy, AllowedFutureBlockTime: base}, ts, b.cfg.Init, b.cfg.ChainID)
	return b
}

// The proposal and finalized header are constructed and signed normally.
// Only the local verification clock and explicit time policy differ.
func TestFutureTimeAllowanceFullLightPair(t *testing.T) {
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", offset, enabled), func(t *testing.T) {
				b := futureTimeBuilder(t, 2, 3)
				h := b.seal(b.propose(0, nil, nil), 0, []int{0, 1, 2})
				now := time.Unix(int64(h.Time)-3, 0).Add(offset)
				env := b.env(h.Time)
				env.Now = func() time.Time { return now }
				env.UseFutureTimeAllowance = enabled
				part := &futureTimeOrderedSteps{}
				env.PartB = part
				err := VerifyHeader(env, h, nil, headerOnly)
				accepted := enabled && offset >= 0
				if accepted && err != nil || !accepted && !errors.Is(err, ErrFutureBlock) {
					t.Fatal("full time policy", err, accepted)
				}
				if accepted && len(part.seen) < 2 || !accepted && len(part.seen) != 0 {
					t.Fatal("H2 skipped ordered checks or ran them after rejection", part.seen)
				}
				lightPart := &futureTimeOrderedSteps{}
				verdict, lightErr := VerifyLight(LightInputs{Config: b.cfg, Trusted: trustChain{b}, PartB: lightPart, Now: env.Now, UseFutureTimeAllowance: enabled}, h, b.head())
				if accepted && (verdict != Valid || lightErr != nil) || !accepted && (verdict != CannotDecide || !errors.Is(lightErr, ErrLightMissing)) {
					t.Fatal("light time policy", verdict, lightErr)
				}
				if accepted && len(lightPart.seen) < 2 || !accepted && len(lightPart.seen) != 0 {
					t.Fatal("light ordered checks", lightPart.seen)
				}
			})
		}
	}
}

func TestFutureTimeAllowanceProposalRetryPair(t *testing.T) {
	for _, allowance := range []uint64{0, 1, 2, 3} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", allowance, enabled), func(t *testing.T) {
				b := futureTimeBuilder(t, allowance, 0)
				h := b.propose(0, nil, nil)
				now := time.Unix(int64(h.Time)-6, 250_000_000)
				env := b.env(h.Time)
				env.Now = func() time.Time { return now }
				env.UseFutureTimeAllowance = enabled
				snapshot, err := source.NewAuthoritySnapshot(b.head().Number, h.ParentHash, b.tip, b.set(h, nil).Addresses(), nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				env.Snapshots = staticSnapshots{h.ParentHash: snapshot}
				part := &futureTimeOrderedSteps{}
				env.PartB = part
				wait, err := VerifyProposal(env, &types.Block{Header: h})
				want := 5750 * time.Millisecond
				if enabled {
					want -= time.Duration(allowance) * time.Second
				}
				if !errors.Is(err, ErrFutureBlock) || wait != want {
					t.Fatal("proposal retry target", wait, want, err)
				}
				if len(part.seen) != 2 || part.seen[0] != "P4" || part.seen[1] != "P5" {
					t.Fatal("proposal ordering before H2", part.seen)
				}
				now = now.Add(wait)
				part.seen = nil
				if next, err := VerifyProposal(env, &types.Block{Header: h}); err != nil || next != 0 {
					t.Fatal("matching retry did not recheck normally", next, err)
				}
				if len(part.seen) <= 2 {
					t.Fatal("later ordered validation did not run", part.seen)
				}
			})
		}
	}
}
