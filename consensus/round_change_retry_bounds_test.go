package consensus

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestNormalRetryPolicyBoundsAndUnsignedIdentityReset(t *testing.T) {
	policy := uint64(0)
	base := types.WBFTParams{RequestTimeoutSeconds: 2, EpochLength: 100, ProposerPolicy: &policy}
	config := types.NewConfig(base, nil, types.GenesisInit{}, nil)
	for _, maximum := range []uint64{0, 1, uint64(math.MaxInt64/int64(time.Millisecond)) + 1, math.MaxUint64} {
		if (&RoundChangeRetryOptions{MaxIntervalMs: maximum}).Validate(config) == nil {
			t.Fatal("invalid explicit maximum accepted", maximum)
		}
	}
	if (&RoundChangeRetryOptions{MaxIntervalMs: 8000}).Validate(nil) == nil {
		t.Fatal("enabled policy lacks actual configuration")
	}
	var disabled *RoundChangeRetryOptions
	if disabled.Validate(nil) != nil {
		t.Fatal("disabled configuration contract changed")
	}
	for _, future := range []uint64{4, 9} {
		config := types.NewConfig(base, []types.Transition{{Block: big.NewInt(20), WBFT: &types.WBFTParams{RequestTimeoutSeconds: future}}}, types.GenesisInit{}, nil)
		if err := (&RoundChangeRetryOptions{MaxIntervalMs: 8000}).Validate(config); (err != nil) != (future > 8) {
			t.Fatal("future effective timeout validation", future, err)
		}
	}
	view := types.View{Sequence: types.HeightFromUint64(10), Round: types.RoundFromUint64(1)}
	empty := &codec.Message{Code: codec.CodeRoundChange, View: view}
	preparedRound := types.RoundFromUint64(0)
	prepared := &codec.Message{Code: codec.CodeRoundChange, View: view, PreparedRound: &preparedRound, PreparedDigest: types.Hash{9}}
	keyA, err := roundChangeRetryKey(empty)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := roundChangeRetryKey(prepared)
	if err != nil || keyA == keyB {
		t.Fatal("unsigned signing identities were conflated", err)
	}
	// This is an unsigned state/identity contract only. No signer or peer
	// receives two different round-change requests for the same view.
	var state roundChangeRetryState
	state.prepare(view, keyA, false)
	for range 80 {
		state.prepare(view, keyA, true)
	}
	if state.exponent != 63 || retryInterval(2000, 8000, state.exponent) != 8*time.Second || retryInterval(2000, 8000, math.MaxUint64) != 8*time.Second {
		t.Fatal("counter or interval did not saturate")
	}
	state.prepare(view, keyB, true)
	if state.exponent != 0 || state.key != keyB {
		t.Fatal("new unsigned message identity retained old spacing")
	}
	state.prepare(view, keyB, true)
	view.Sequence = view.Sequence.AddUint64(1)
	state.prepare(view, keyB, true)
	if state.exponent != 0 || state.view.Cmp(view) != 0 {
		t.Fatal("full height identity retained old spacing")
	}
}

func TestNormalRetryNewHeightResetsCandidate(t *testing.T) {
	h := normalRetryHarness(t, true, false)
	h.roundTimeout()
	for range 2 {
		h.step(queuedRetryExpiry(t, h))
	}
	if h.vars().RoundChangeRetry == nil || h.vars().RoundChangeRetry.Exponent != 2 {
		t.Fatal("current retry prefix missing")
	}
	previous := h.vars().View.Sequence
	next := h.proposal(1)
	next.Header.ParentHash = codec.BlockHash(h.env.head.Header)
	h.env.head = next
	h.step(NewHead{Header: next.Header})
	if h.vars().View.Sequence.Cmp(previous.AddUint64(1)) != 0 || h.vars().RoundChangeRetry != nil {
		t.Fatal("ordinary new head retained previous retry candidate")
	}
	h.roundTimeout()
	arm := normalRetryArm(t, h)
	if arm.Duration != 2*time.Second || arm.Retry == nil || arm.Retry.Exponent != 0 {
		t.Fatal("next-height first interval changed", arm)
	}
}
