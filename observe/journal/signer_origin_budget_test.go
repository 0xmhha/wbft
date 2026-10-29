package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
)

func normalOriginBudget(t *testing.T) *originBudget {
	t.Helper()
	b, err := newOriginBudget(SignerOriginLimits{
		Core:    CoreSourceLimits{Records: 100, Runs: 10, Steps: 100, Environments: 100, Outputs: 100, Bytes: 1 << 20},
		Signer:  privval.SourceLimits{Lifetimes: 10, Operations: 100, Records: 100, Bytes: 1 << 20},
		Writers: 10, Links: 10, Frames: 100, Bytes: 1 << 20, Work: 1 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignerOriginBudgetArithmetic(t *testing.T) {
	if _, err := originAdd(math.MaxUint64, 1); err == nil {
		t.Fatal("addition overflow accepted")
	}
	if _, err := originMul(math.MaxUint64, 2); err == nil {
		t.Fatal("multiplication overflow accepted")
	}
	if v, err := originMul(math.MaxUint64, 0); err != nil || v != 0 {
		t.Fatal("zero product differs", v, err)
	}
	left, used := uint64(3), uint64(0)
	if err := originTake(&left, &used, 2, "limit"); err != nil || left != 1 || used != 2 {
		t.Fatal("initial reservation differs")
	}
	if err := originTake(&left, &used, 2, "limit"); err == nil || left != 1 || used != 2 {
		t.Fatal("exhausted reservation changed counters")
	}
	b := normalOriginBudget(t)
	if err := b.lease(math.MaxUint64, 16, true); err == nil || b.usage.Work != 0 {
		t.Fatal("overflow lease ran or charged wrapped amount")
	}
}

func TestSignerOriginBudgetWholeCall(t *testing.T) {
	b := normalOriginBudget(t)
	b.left.Core.Records = 3
	if err := b.core(CoreSourceLimits{Records: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.core(CoreSourceLimits{Records: 2}); err == nil || b.usage.Core.Records != 2 {
		t.Fatal("child reused full record quota")
	}
	b.left.Signer.Operations = 3
	if err := b.signer(privval.SourceLimits{Operations: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.signer(privval.SourceLimits{Operations: 2}); err == nil || b.usage.Signer.Operations != 2 {
		t.Fatal("child reused full signer quota")
	}
	before := b.usage.Work
	if err := b.lease(10, 4, false); err != nil {
		t.Fatal(err)
	}
	if err := b.lease(10, 4, false); err != nil {
		t.Fatal(err)
	}
	if b.usage.Work-before != 82 {
		t.Fatal("repeated decoder passes were not charged separately")
	}
	before = b.usage.Work
	if err := b.lease(10, 16, true); err != nil {
		t.Fatal(err)
	}
	if b.usage.Work-before != 16*(1+10+100) {
		t.Fatal("core reservation differs from q(p) contract")
	}
}

type originMarshalProbe struct {
	Calls *int
	Data  []byte
}

func (p *originMarshalProbe) MarshalJSON() ([]byte, error) {
	*p.Calls++
	return nil, errors.New("must not be called during structural preflight")
}

func TestSignerOriginBudgetPreflight(t *testing.T) {
	data := []byte{1, 2, 3}
	copy := bytes.Clone(data)
	calls := 0
	b := normalOriginBudget(t)
	shape, err := b.shape(&originMarshalProbe{Calls: &calls, Data: data})
	if err != nil || calls != 0 || !bytes.Equal(copy, data) || shape.nodes == 0 || shape.span <= uint64(len(data)) {
		t.Fatal("preflight invoked methods, changed bytes, or lost structural accounting", shape, err)
	}
	if b.usage.Bytes != uint64(len(data)) {
		t.Fatal("structural overhead mislabeled as retained byte span", b.usage.Bytes)
	}
	limited := normalOriginBudget(t)
	limited.left.Bytes = 2
	if _, err := limited.shape(data); err == nil {
		t.Fatal("byte limit was not applied before decoding")
	}
	for _, n := range []*big.Int{new(big.Int), big.NewInt(256)} {
		if _, err := b.shape(n); err != nil {
			t.Fatal("public chain integer preflight failed", err)
		}
	}
	if _, err := b.shape(map[string]any{"number": 1.5, "bytes": data}); err != nil {
		t.Fatal("ordinary diagnostic map preflight failed", err)
	}
	type link struct{ Next *link }
	cycle := new(link)
	cycle.Next = cycle
	if _, err := b.shape(cycle); err == nil {
		t.Fatal("cyclic unsigned metadata escaped the preflight depth bound")
	}
}

func TestSignerOriginNilNodeDelegation(t *testing.T) {
	limits := NodeExecutionLimits{}
	old, err := CheckRestoredNodeExecutionSources(context.Background(), nil, nil, nil, limits)
	for _, origins := range []*SignerOriginSources{nil, {}} {
		got, e := CheckRestoredNodeExecutionSourcesWithSignerOrigins(context.Background(), nil, nil, nil, limits, origins, SignerOriginLimits{})
		if !reflect.DeepEqual(got.Legacy, old) || fmt.Sprint(err) != fmt.Sprint(e) || got.OriginStatus != "not_requested" || got.Status != old.Status || got.Reason != old.Reason || got.Scope != old.Scope || got.Application.Status != "" {
			t.Fatal("nil origin changed or completed the legacy partial result", got, e)
		}
	}
}

func TestSignerOriginUnsignedStateEntryQuota(t *testing.T) {
	// These are fresh unsigned list shapes for quota inspection, not signing
	// requests, signed state transitions or actor inputs.
	state := func(entries []rlp.RawValue) []byte {
		raw, e := rlp.Encode([]any{uint64(0), uint64(0), uint64(0), uint64(0), entries, []rlp.RawValue{}})
		if e != nil {
			t.Fatal(e)
		}
		return append([]byte{1}, raw...)
	}
	empty := state(nil)
	attempted := state([]rlp.RawValue{rlp.EmptyList, rlp.EmptyList})
	source := privval.Source{Before: empty, After: empty, Write: attempted}
	b := normalOriginBudget(t)
	quota, err := originSignerQuota(b, []privval.Source{source})
	if err != nil || quota.Records != 3 || b.usage.Signer.Records != 3 {
		t.Fatal("attempted write entries omitted from global quota", quota, b.usage, err)
	}
	b = normalOriginBudget(t)
	b.left.Signer.Records = 2
	if _, err := originSignerQuota(b, []privval.Source{source}); err == nil || b.failure == nil {
		t.Fatal("attempted write exceeded its global quota without an inspection interruption")
	}
}

func TestSignerOriginNodePreflightBudget(t *testing.T) {
	limits := normalOriginBudget(t).left
	limits.Work = 1
	origins := &SignerOriginSources{Prior: []SignerOriginRun{{}}, Links: []SignerOriginLink{{}}}
	got, err := CheckRestoredNodeExecutionSourcesWithSignerOrigins(context.Background(), nil, nil, nil, NodeExecutionLimits{}, origins, limits)
	if err != nil || got.Status != "unavailable" || got.Signer.CurrentInspected || got.Signer.Usage.Work > 1 || got.Signer.Usage.Work == 0 || got.Application.Status != "" {
		t.Fatal("Node preflight lost partial budget or completed an unchecked component", got, err)
	}
}

func TestSignerOriginMissingDomainUnavailable(t *testing.T) {
	// Fresh unsigned declarations omit the required domain. The checker must
	// not invent a genesis, chain, local identity, mode or wire domain.
	origins := &SignerOriginSources{Prior: []SignerOriginRun{{Records: []Record{{Body: &SegmentRec{Identity: Identity{Run: "prior", Core: CoreOptions{ChainConfig: []byte("{}")}}}}}}}, Links: []SignerOriginLink{{}}}
	rows := []Record{{Body: &SegmentRec{Identity: Identity{Run: "current", Core: CoreOptions{ChainConfig: []byte("{}")}}}}}
	limits := normalOriginBudget(t).left
	_, _, _, got, err := CheckRestoredSignerSourcesWithOrigins(rows, limits.Core, limits.Signer, origins, limits)
	if err != nil || got.Status != "unavailable" || !strings.Contains(got.Reason, "origin_domain_missing") || got.CurrentInspected {
		t.Fatal("missing domain was inferred or mislabeled as current inspection", got, err)
	}
}
