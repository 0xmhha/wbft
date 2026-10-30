package journal

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func domainDeclarationModel(t *testing.T) (Identity, consensus.Options) {
	t.Helper()
	raw := []byte(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":10}}}`)
	cfg, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := types.DomainForConfig(cfg, types.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	description, err := codec.EncodeRoundChangeDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Run: "domain-model", ChainID: big.NewInt(7), GenesisHash: types.Hash{1}, Core: CoreOptions{ChainConfig: raw, DomainBytes: description}}, consensus.Options{Config: cfg, RoundChangeDomain: domain}
}

// All negative declarations are unsigned, detached metadata models.
func TestRoundChangeDomainDeclarationCodecIdentityAndOwnership(t *testing.T) {
	id, options := domainDeclarationModel(t)
	if err := id.ValidateDomainIdentity(); err != nil {
		t.Fatal(err)
	}
	if err := id.Core.ValidateCoreDeclaration(options); err != nil {
		t.Fatal(err)
	}
	copy := id.Core.Copy()
	copy.DomainBytes[0] ^= 1
	if bytes.Equal(copy.DomainBytes, id.Core.DomainBytes) {
		t.Fatal("copied declaration shares domain storage")
	}
	wire, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindSegment, wire)
	if err != nil {
		t.Fatal(err)
	}
	segment := decoded.Body.(*SegmentRec)
	if err := segment.ValidateDomainIdentity(); err != nil || !bytes.Equal(segment.Core.DomainBytes, id.Core.DomainBytes) {
		t.Fatal("segment did not retain its explicit domain", err)
	}
	for _, change := range []func(*Identity){
		func(id *Identity) { id.ChainID = big.NewInt(8) },
		func(id *Identity) { id.GenesisHash = types.Hash{2} },
		func(id *Identity) { id.Core.DomainBytes = nil },
	} {
		model := id
		change(&model)
		if err := model.ValidateDomainIdentity(); err == nil {
			t.Fatal("inconsistent unsigned identity granted a domain")
		}
	}
	fs := fsys.NewMem()
	writer, err := Open(Options{FS: fs, Dir: "/domain", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	id.Core.DomainBytes[0] ^= 1
	if bytes.Equal(writer.CoreDeclaration().DomainBytes, id.Core.DomainBytes) {
		t.Fatal("writer declaration aliases caller bytes")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRoundChangeDomainCoreStepProfileAndQueueCost(t *testing.T) {
	id, _ := domainDeclarationModel(t)
	legacy := minimalCoreSource(t)
	legacyRaw, err := encodeCoreStepRec(legacy, 1)
	if err != nil {
		t.Fatal(err)
	}
	var oldWire coreStepRLP
	if err := rlp.DecodeStrict(legacyRaw, &oldWire); err != nil || oldWire.Profile != 1 || len(oldWire.DomainBytes) != 0 {
		t.Fatal("legacy source acquired a declaration", err)
	}
	selected := *legacy
	selected.DomainBytes = bytes.Clone(id.Core.DomainBytes)
	raw, err := encodeCoreStepRec(&selected, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCoreStepRec(raw)
	if err != nil || !bytes.Equal(decoded.Body.(*CoreStepRec).DomainBytes, selected.DomainBytes) {
		t.Fatal("profile2 source lost its declaration", err)
	}
	var wire coreStepRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil || wire.Profile != 2 {
		t.Fatal("selected source retained profile1", err)
	}
	for _, change := range []func(*coreStepRLP){
		func(w *coreStepRLP) { w.Profile = 1 },
		func(w *coreStepRLP) { w.DomainBytes = nil },
	} {
		model := wire
		change(&model)
		bad, err := rlp.Encode(model)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeCoreStepRec(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("inconsistent supported profile was not malformed", err)
		}
	}
	unknown := wire
	unknown.Profile++
	bad, err := rlp.Encode(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCoreStepRec(bad); !errors.Is(err, ErrDomainSourceUnsupported) {
		t.Fatal("future profile was not unsupported", err)
	}
	if size(Record{Body: &selected})-size(Record{Body: legacy}) != int64(len(selected.DomainBytes)) {
		t.Fatal("core source queue omitted domain bytes")
	}
	base := &SignerRec{Source: privval.Source{}}
	domainSource := *base
	domainSource.Source.DomainBytes = selected.DomainBytes
	if size(Record{Body: &domainSource})-size(Record{Body: base}) != int64(len(selected.DomainBytes)) {
		t.Fatal("signer source queue omitted domain bytes")
	}
}
