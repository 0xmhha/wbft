package journal

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/types"
)

func unsignedDomainSource(t *testing.T, entries []rlp.RawValue) privval.Source {
	t.Helper()
	domain, err := types.NewRoundChangeDomain(big.NewInt(7), types.Hash{1}, types.HeightFromUint64(3))
	if err != nil {
		t.Fatal(err)
	}
	description, _ := codec.EncodeRoundChangeDomain(domain)
	inner, err := rlp.Encode([]any{uint64(0), uint64(0), uint64(0), uint64(0), entries, []rlp.RawValue{}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := rlp.Encode([]any{uint64(1), big.NewInt(7), domain.GenesisHash(), big.NewInt(3), types.Address{1}, append([]byte{1}, inner...)})
	if err != nil {
		t.Fatal(err)
	}
	state := append([]byte{2}, body...)
	return privval.Source{Version: 2, Ref: privval.SourceRef{Namespace: "domain-reader", Signer: 1, Sequence: 1}, Address: types.Address{1}, Action: "initial", Result: "ok", Before: state, After: bytes.Clone(state), DomainBytes: description}
}

func TestDomainSignerJournalCanonicalPublicSource(t *testing.T) {
	source := unsignedDomainSource(t, nil)
	raw, err := encodeBody(Record{Body: &SignerRec{Source: source}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindSigner, raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("versioned signer source lost canonical bytes", err)
	}
	back := decoded.Body.(*SignerRec).Source
	if back.Version != 2 || !bytes.Equal(back.DomainBytes, source.DomainBytes) {
		t.Fatal("journal lost domain declaration")
	}
	report, err := privval.CheckSources([]privval.Source{back}, privval.SourceLimits{Lifetimes: 1, Operations: 1, Records: 4, Bytes: 1 << 20})
	if err != nil || report.Status != "consistent" || report.PhysicalStatus != "unavailable" {
		t.Fatal("public initial witness was not conditionally checked", report, err)
	}
}

func TestDomainSignerOriginUnsignedEnvelopeQuota(t *testing.T) {
	// Only detached unsigned list shapes are counted. These are not actual
	// signed-state entries or evidence of a completed runtime restore.
	source := unsignedDomainSource(t, nil)
	source.Write = unsignedDomainSource(t, []rlp.RawValue{rlp.EmptyList, rlp.EmptyList}).Before
	budget := normalOriginBudget(t)
	quota, err := originSignerQuota(budget, []privval.Source{source})
	expectedBytes := uint64(1 + len(source.Before) + len(source.After) + len(source.Write) + len(source.Ref.Namespace) + len(source.DomainBytes))
	if err != nil || quota.Records != 3 || quota.Bytes != expectedBytes || budget.usage.Signer.Bytes != expectedBytes {
		t.Fatal("envelope or declaration escaped the origin quota", quota, budget.usage, err)
	}
}

func TestDomainSignerJournalUnsupportedAndMalformedAreDistinct(t *testing.T) {
	source := unsignedDomainSource(t, nil)
	future, err := rlp.Encode([]any{uint64(2), big.NewInt(7), types.Hash{1}, big.NewInt(3)})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"domain_version", "source_version", "malformed"} {
		candidate := source
		switch mode {
		case "domain_version":
			candidate.DomainBytes = future
		case "source_version":
			candidate.Version = 3
		case "malformed":
			candidate.DomainBytes = []byte{0xc0}
		}
		// Encode only unsigned detached metadata, never a runtime journal.
		raw, err := rlp.Encode(signerRLP{Format, 1, SignerRec{Source: candidate}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeSignerRec(raw)
		if mode == "malformed" {
			if !errors.Is(err, ErrRecord) || errors.Is(err, ErrSignerSourceUnsupported) {
				t.Fatal("malformed source granted unsupported classification", err)
			}
		} else if !errors.Is(err, ErrSignerSourceUnsupported) || errors.Is(err, ErrRecord) {
			t.Fatal("future profile mislabeled as corruption", mode, err)
		}
	}
}
