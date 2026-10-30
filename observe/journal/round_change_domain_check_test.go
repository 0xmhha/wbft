package journal

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// Each transcript executes its own unsigned core Start/Stop model. It is not
// an authenticated genesis, live actor, packet delivery or physical WAL proof.
func domainCoreTranscript(t *testing.T, writer string, genesis byte) []Record {
	t.Helper()
	id, options := domainDeclarationModel(t)
	domain, err := types.DomainForConfig(options.Config, types.Hash{genesis})
	if err != nil {
		t.Fatal(err)
	}
	options.RoundChangeDomain = domain
	id.Run, id.GenesisHash = writer, domain.GenesisHash()
	id.Core.DomainBytes, err = codec.EncodeRoundChangeDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	state, err := consensus.NewStateChecked(options)
	if err != nil {
		t.Fatal(err)
	}
	head := &types.Header{Number: types.HeightFromUint64(9), Difficulty: big.NewInt(1)}
	headBytes, err := codec.EncodeHeader(head)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := validator.NewSet([]types.Address{{1}, {2}, {3}, {4}}, make([][]byte, 4), types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{{Body: &SegmentRec{Identity: id}}}
	for i, in := range []consensus.Input{consensus.Start{}, consensus.Stop{}} {
		env := &coreSourceEnv{head: head}
		var observed []CoreEnvObservation
		if i == 0 {
			answer := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: head.Number.AddUint64(1), Key: codec.BlockHash(head), Validators: vs}
			env.answers = []inputlog.EnvCall{answer}
			raw, err := inputlog.EncodeEnv(answer)
			if err != nil {
				t.Fatal(err)
			}
			observed = []CoreEnvObservation{{Bytes: raw, ValidatorKeyPresent: make([]bool, vs.Len())}}
		}
		before, knownBefore, err := coreSourceContext(state.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		outputs := state.Step(env, in)
		if env.err != nil || len(env.answers) != 0 {
			t.Fatal("normal model environment differs", env.err)
		}
		input, err := inputlog.Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := inputlog.EncodeOutputs(outputs)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := inputlog.OutDigest(outputs)
		if err != nil {
			t.Fatal(err)
		}
		after, knownAfter, err := coreSourceContext(state.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, Record{Body: &CoreStepRec{DomainBytes: bytes.Clone(id.Core.DomainBytes), EngineRun: 1, Step: uint64(i + 1), Via: "engine",
			InputKind: inputlog.Kind(in), Input: input, Outputs: encoded, OutDigest: digest, Head: headBytes, Environment: observed,
			Before: before, BeforeKnown: knownBefore, After: after, AfterKnown: knownAfter,
			Entry: CoreStepMoment{Mono: int64(2*i + 1)}, Observed: CoreStepMoment{Mono: int64(2*i + 2)}}})
	}
	return records
}

func TestRoundChangeDomainCoreWriterScopeAndSpan(t *testing.T) {
	a, b := domainCoreTranscript(t, "a", 1), domainCoreTranscript(t, "b", 2)
	limits := CoreSourceLimits{Records: 100, Runs: 4, Steps: 20, Environments: 20, Outputs: 100, Bytes: 1 << 20}
	interleaved := []Record{a[0], a[1], b[0], b[1], a[0], a[2], b[0], b[2]}
	check, err := CheckCoreStepSources(interleaved, limits)
	if err != nil || check.Status != "consistent" || check.Runs != 2 || check.Steps != 4 {
		t.Fatal("interleaved writers borrowed a different context", check, err)
	}
	model := *a[1].Body.(*CoreStepRec)
	model.DomainBytes = b[1].Body.(*CoreStepRec).DomainBytes
	check, err = CheckCoreStepSources([]Record{a[0], {Body: &model}}, limits)
	if err == nil || check.Status != "inconsistent" || check.Reason != "actual_core_options_changed" {
		t.Fatal("unsigned step borrowed a different writer's domain", check, err)
	}
	model.DomainBytes = nil
	check, err = CheckCoreStepSources([]Record{a[0], {Body: &model}}, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "round_change_domain_context_unavailable" {
		t.Fatal("selected step without a declaration became legacy", check, err)
	}
	model.DomainBytes, err = rlp.Encode([]any{types.RoundChangeDomainVersion + 1, big.NewInt(7), types.Hash{1}, big.NewInt(10)})
	if err != nil {
		t.Fatal(err)
	}
	check, err = CheckCoreStepSources([]Record{a[0], {Body: &model}}, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "round_change_domain_context_unavailable" {
		t.Fatal("future step description became malformed", check, err)
	}
	segment := *a[0].Body.(*SegmentRec)
	segment.Core.DomainBytes = nil
	check, err = CheckCoreStepSources([]Record{{Body: &segment}, a[1]}, limits)
	if err != nil || check.Status != "unavailable" {
		t.Fatal("missing selected context became legacy", check, err)
	}
	var span uint64
	for _, record := range a {
		switch r := record.Body.(type) {
		case *SegmentRec:
			span += uint64(len(r.Core.ChainConfig) + len(r.Core.DomainBytes))
		case *CoreStepRec:
			span += uint64(len(r.Input) + len(r.Outputs) + len(r.Head) + len(r.DomainBytes))
			for _, e := range r.Environment {
				span += uint64(len(e.Bytes) + len(e.ValidatorKeyPresent))
			}
		}
	}
	limits.Bytes = span
	check, err = CheckCoreStepSources(a, limits)
	if err != nil || check.Status != "consistent" {
		t.Fatal("exact declared byte span was refused", check, err)
	}
	limits.Bytes--
	check, err = CheckCoreStepSources(a, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "source_byte_limit" {
		t.Fatal("domain bytes escaped the inspection cap", check, err)
	}
	restored, err := CheckRestoreSources(a, CoreSourceLimits{Records: 100, Runs: 4, Steps: 20, Environments: 20, Outputs: 100, Bytes: 1 << 20})
	if err != nil || restored.Status != "unavailable" || restored.Reason != "round_change_domain_profile" {
		t.Fatal("new profile gained legacy full-restore capability", restored, err)
	}
}

func TestRoundChangeDomainSignerDeclarationBindingWithoutSignatures(t *testing.T) {
	source := unsignedDomainSource(t, nil)
	if err := matchSignerDomain(source, source.DomainBytes); err != nil {
		t.Fatal(err)
	}
	id, _ := domainDeclarationModel(t) // Same CID/genesis, different activation.
	if err := matchSignerDomain(source, id.Core.DomainBytes); !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("unsigned initial state borrowed another activation", err)
	}
	legacy := privval.Source{Version: privval.SourceVersion}
	if err := matchSignerDomain(legacy, nil); err != nil {
		t.Fatal(err)
	}
	if err := matchSignerDomain(legacy, source.DomainBytes); !errors.Is(err, types.ErrRoundChangeDomain) {
		t.Fatal("legacy source granted a selected lifetime", err)
	}
	future := source
	future.Version++
	if err := matchSignerDomain(future, source.DomainBytes); !errors.Is(err, ErrSignerSourceUnsupported) {
		t.Fatal("future signer version became malformed", err)
	}
	missing := source
	missing.DomainBytes = nil
	if err := matchSignerDomain(missing, source.DomainBytes); !errors.Is(err, privval.ErrSource) || errors.Is(err, ErrSignerSourceUnsupported) {
		t.Fatal("unmarked supported source lost its malformed shape", err)
	}
	missing.Unavailable = "domain_declaration_unavailable"
	if err := matchSignerDomain(missing, source.DomainBytes); !errors.Is(err, ErrSignerSourceUnsupported) {
		t.Fatal("explicit omission marker lost its unavailable boundary", err)
	}
}

func TestRoundChangeDomainInternalOwnNormalRecovery(t *testing.T) {
	secret := make([]byte, 32)
	secret[31] = 1
	key, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		t.Fatal(err)
	}
	self := ecdsa.Address(key)
	vs, err := validator.NewSet([]types.Address{self}, [][]byte{nil}, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []uint64{3, 100} {
		domain, err := types.NewRoundChangeDomain(big.NewInt(7), types.Hash{1}, types.HeightFromUint64(at))
		if err != nil {
			t.Fatal(err)
		}
		m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(10), Round: types.RoundFromUint64(1)}}
		body, err := codec.SigningPayloadWithDomain(m, domain)
		if err != nil {
			t.Fatal(err)
		}
		signed := *m
		signed.Signature, err = ecdsa.SignData(body, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := codec.EncodeMessage(&signed)
		if err != nil {
			t.Fatal(err)
		}
		declared, err := codec.EncodeRoundChangeDomain(domain)
		if err != nil {
			t.Fatal(err)
		}
		expected := &internalExpected{source: &CoreStepRec{CoreSelf: self, DomainBytes: declared, Entry: CoreStepMoment{Mono: 1}}, broadcast: &consensus.Broadcast{Msg: m, Validators: vs}}
		if !matchInternalOwn(consensus.Message{Peer: self, Code: m.Code, Payload: raw, RecvMono: 1}, &InternalRec{Mono: 2}, expected) {
			t.Fatal("own intact message did not match its declared context", at)
		}
	}
}
