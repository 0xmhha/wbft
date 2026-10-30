package privval

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// This is the unchanged pre-domain wire schema, independent of Source's new
// optional tail. It catches accidental nil-field additions to legacy bytes.
type legacySourceWire struct {
	Version           uint64
	Ref               SourceRef
	Address           types.Address
	BLSPublicKey      []byte
	Action            string
	Before, After     []byte
	RequestCode       uint64
	Request, SealData []byte
	BadBlockReleased  uint64
	Floor             string
	Signature, Seal   []byte
	Reused            uint64
	Result            string
	WriteAttempted    uint64
	Write             []byte
	WriteResult       string
	Unavailable       string
}

func TestDomainSourceLegacyWireAndJSONRemainExact(t *testing.T) {
	old := legacySourceWire{Version: 1, Ref: SourceRef{"old-signer", 3, 4}, Address: types.Address{1},
		Action: "initial", Result: "ok", Unavailable: "inspection_limits_required"}
	current := Source{Version: 1, Ref: old.Ref, Address: old.Address, Action: old.Action, Result: old.Result, Unavailable: old.Unavailable}
	want, err := rlp.Encode(old)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rlp.Encode(current)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("legacy source RLP changed", err)
	}
	wantJSON, _ := json.Marshal(old)
	gotJSON, _ := json.Marshal(current)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatal("legacy source JSON gained fields")
	}
	// Merely relabeling an old unavailable witness is not a valid v2 source.
	current.Version = DomainSourceVersion
	if ValidateSource(current) == nil {
		t.Fatal("legacy unavailable witness silently promoted")
	}
}

func TestDomainSourceMetadataBoundsAndVersionClassification(t *testing.T) {
	domain := signerDomain(t, 3)
	var sources []Source
	options := Options{FS: fsys.NewMem(), RoundChangeDomain: domain,
		Sources: &SourceOptions{Namespace: "bounded-domain-signer", Records: 16, Bytes: 1 << 20, Observe: func(s Source) { sources = append(sources, s) }}}
	if _, err := NewKeySignerWithOptions(options, testKey(43), "/bounded/state"); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || len(sources[0].DomainBytes) == 0 {
		t.Fatal("domain declaration missing")
	}
	source := sources[0]
	var withoutDomain uint64
	for _, value := range [][]byte{source.BLSPublicKey, source.Before, source.After, source.Request, source.SealData, source.Signature, source.Seal, source.Write, []byte(source.Floor), []byte(source.Ref.Namespace)} {
		withoutDomain += uint64(len(value))
	}
	limits := SourceLimits{Lifetimes: 4, Operations: 64, Records: 128, Bytes: withoutDomain}
	report, err := CheckSources(sources, limits)
	if err != nil || report.Status != "unavailable" || report.Reason != "byte_limit" {
		t.Fatal("declaration bytes escaped the inspection quota", report, err)
	}
	// These are detached public metadata arrays; no signer is used below.
	future, _ := rlp.Encode([]any{uint64(2), big.NewInt(7), domain.GenesisHash(), big.NewInt(3)})
	source.DomainBytes = future
	limits.Bytes = 1 << 20
	report, err = CheckSources([]Source{source}, limits)
	if err != nil || report.Status != "unavailable" || report.Reason != "domain_version_unsupported" {
		t.Fatal("unknown domain version mislabeled as corruption", report, err)
	}
	source.DomainBytes = []byte{0xc0}
	report, err = CheckSources([]Source{source}, limits)
	if err == nil || report.Status != "inconsistent" {
		t.Fatal("malformed declared domain accepted", report, err)
	}
	source.Version = 3
	report, err = CheckSources([]Source{source}, limits)
	if err != nil || report.Status != "unavailable" || report.Reason != "source_version_unsupported" {
		t.Fatal("unknown source version granted a verdict", report, err)
	}
}

func TestDomainSourceTinyObserverIsExplicitlyUnavailable(t *testing.T) {
	var sources []Source
	options := Options{FS: fsys.NewMem(), RoundChangeDomain: signerDomain(t, 3),
		Sources: &SourceOptions{Namespace: "tiny-domain-signer", Records: 1, Bytes: 1, Observe: func(s Source) { sources = append(sources, s) }}}
	if _, err := NewKeySignerWithOptions(options, testKey(44), "/tiny/state"); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Version != 2 || sources[0].Unavailable != "domain_declaration_unavailable" || len(sources[0].DomainBytes) != 0 || ValidateSource(sources[0]) != nil {
		t.Fatal("bounded missing declaration did not remain explicit")
	}
	if _, err := codec.DecodeRoundChangeDomain(sources[0].DomainBytes); err != nil {
		t.Fatal("empty declaration encoding changed", err)
	}
}
