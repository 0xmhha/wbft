package stepdriver

import (
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestRoundChangeDomainSegmentContextClassification(t *testing.T) {
	raw := []byte(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":10}}}`)
	config, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := types.DomainForConfig(config, types.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := codec.EncodeRoundChangeDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	segment := &journal.SegmentRec{Identity: journal.Identity{Run: "declared-domain", ChainID: big.NewInt(7), GenesisHash: types.Hash{1}, Core: journal.CoreOptions{ChainConfig: raw, DomainBytes: declaration}}}
	got, err := segmentDomain(segment)
	if err != nil || !got.Equal(domain) {
		t.Fatal("matching segment context was not retained", err)
	}
	missing := *segment
	missing.Core.DomainBytes = nil
	if _, err := segmentDomain(&missing); !errors.Is(err, ErrUnsupported) {
		t.Fatal("missing selected context became legacy", err)
	}
	wrong := *segment
	wrong.GenesisHash = types.Hash{2}
	if _, err := segmentDomain(&wrong); !errors.Is(err, ErrTraceConfiguration) || errors.Is(err, ErrUnsupported) {
		t.Fatal("supported inconsistent identity lost its classification", err)
	}
	future := *segment
	future.Core.DomainBytes, err = rlp.Encode([]any{types.RoundChangeDomainVersion + 1, big.NewInt(7), types.Hash{1}, big.NewInt(10)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := segmentDomain(&future); !errors.Is(err, ErrUnsupported) {
		t.Fatal("future description was treated as a malformed supported context", err)
	}
	if domain, err := segmentDomain(&journal.SegmentRec{}); err != nil || domain != nil {
		t.Fatal("legacy-only segment acquired a context", err)
	}
}

func TestRoundChangeDomainTraceKeepsReappearingWriterDeclaration(t *testing.T) {
	raw := []byte(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":10}}}`)
	config, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	segment := func(writer string, genesis byte) *journal.SegmentRec {
		t.Helper()
		domain, err := types.DomainForConfig(config, types.Hash{genesis})
		if err != nil {
			t.Fatal(err)
		}
		declared, err := codec.EncodeRoundChangeDomain(domain)
		if err != nil {
			t.Fatal(err)
		}
		return &journal.SegmentRec{Identity: journal.Identity{Run: writer, ChainID: big.NewInt(7), GenesisHash: domain.GenesisHash(), Core: journal.CoreOptions{ChainConfig: raw, DomainBytes: declared}}}
	}
	a, b, changedA := segment("a", 1), segment("b", 2), segment("a", 3)
	reader := &coverageReader{records: []journal.Record{{Body: a}, {Body: b}, {Body: changedA}}}
	if err := RunTrace(reader, TraceOptions{}, func(StepResult) error { return nil }); !errors.Is(err, ErrTraceConfiguration) {
		t.Fatal("reappearing writer changed its selected context", err)
	}
	reader = &coverageReader{records: []journal.Record{{Body: a}, {Body: b}, {Body: a}}}
	if err := RunTrace(reader, TraceOptions{}, func(StepResult) error { return nil }); err != nil {
		t.Fatal("same declared writer could not reappear", err)
	}
}

func TestRoundChangeDomainDescriptionCapsPrecedeDecoding(t *testing.T) {
	segment := &journal.SegmentRec{Identity: journal.Identity{Run: "oversized-model", Core: journal.CoreOptions{DomainBytes: make([]byte, MaxApplicationAnswerBytes+1)}}}
	if _, err := segmentDomain(segment); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("oversized unsigned description reached decoding", err)
	}
	reader := &coverageReader{records: []journal.Record{{JSeq: 1, Body: segment}}}
	if _, err := NewAnswerPool(reader); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("answer index omitted description bytes", err)
	}
}

func TestRoundChangeDomainWriterIndexFiniteLegacyBoundary(t *testing.T) {
	legacy := newTraceDomainIndex(2, 128)
	for _, writer := range []string{"a", "b", "c", "d"} {
		if err := legacy.observe(writer, [32]byte{1}, false); err != nil {
			t.Fatal("legacy-only stream acquired a new refusal", err)
		}
	}
	if !legacy.overflow || len(legacy.owners) != 0 || legacy.bytes != 0 {
		t.Fatal("legacy prefix retained an unbounded owner index")
	}
	if err := legacy.observe("selected", [32]byte{2}, true); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("incomplete legacy prefix granted selected writer proof", err)
	}
	selected := newTraceDomainIndex(2, 128)
	if err := selected.observe("a", [32]byte{1}, true); err != nil {
		t.Fatal(err)
	}
	if err := selected.observe("a", [32]byte{2}, true); !errors.Is(err, ErrTraceConfiguration) {
		t.Fatal("selected writer changed inside the bounded index", err)
	}
	if err := selected.observe("b", [32]byte{1}, false); err != nil {
		t.Fatal(err)
	}
	if err := selected.observe("c", [32]byte{1}, false); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("selected prefix escaped its owner count cap", err)
	}
	bytes := newTraceDomainIndex(10, 34)
	if err := bytes.observe("a", [32]byte{1}, true); err != nil || bytes.bytes != 34 {
		t.Fatal("exact owner byte span refused", err)
	}
	if err := bytes.observe("b", [32]byte{1}, false); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("owner name/hash bytes escaped the cap", err)
	}
}
