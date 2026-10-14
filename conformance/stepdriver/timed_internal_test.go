package stepdriver

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestTimedInternalPreservesNestedSigningEvidence(t *testing.T) {
	nested := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(9), Round: types.RoundFromUint64(1)}, Signature: []byte{1}, Seal: []byte{2}}
	original := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(9), Round: types.RoundFromUint64(2)}, Prepares: []*codec.Message{nested}}
	signed := *original
	signed.Signature = []byte{3}
	payload, err := codec.EncodeMessage(&signed)
	if err != nil {
		t.Fatal(err)
	}
	output := consensus.Broadcast{Msg: original}
	input := consensus.Message{Code: signed.Code, Payload: payload}
	if ok, err := matchesInternal(output, input); err != nil || !ok {
		t.Fatal("matching signing result rejected", ok, err)
	}
	otherNested := *nested
	otherNested.Signature = []byte{4}
	other := *original
	other.Prepares = []*codec.Message{&otherNested}
	if ok, err := matchesInternal(consensus.Broadcast{Msg: &other}, input); err != nil || ok {
		t.Fatal("nested certificate replaced", ok, err)
	}
}
func TestTimedSigningPoolRequiresWholeRequestAndSingleOrderedEvidence(t *testing.T) {
	head := types.Hash{1}
	a := TimedSource{Writer: "synthetic", Engine: 1, Step: 1, Ordinal: 1}
	b := TimedSource{Writer: "synthetic", Engine: 1, Step: 2, Ordinal: 2}
	out := consensus.Broadcast{Msg: &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(9)}}, SealData: []byte{1}}
	signed := *out.Msg
	signed.Signature = []byte{2}
	signed.Seal = []byte{3}
	payload, err := codec.EncodeMessage(&signed)
	if err != nil {
		t.Fatal(err)
	}
	in := consensus.Message{Code: signed.Code, Payload: payload}
	makePool := func() *timedSigningPool {
		p, err := newTimedSigningPool(map[timedOutputKey]timedSigningEvidence{{a, 0}: {out, in, b}}, map[TimedSource]timedSourceEntry{a: {record: &journal.StepRec{HeadHash: head}}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, variant := range []string{"head", "writer", "engine", "sealdata", "release"} {
		t.Run(variant, func(t *testing.T) {
			p := makePool()
			changed := out
			writer, engine, h := "synthetic", uint64(1), head
			switch variant {
			case "head":
				h = types.Hash{2}
			case "writer":
				writer = "other"
			case "engine":
				engine = 2
			case "sealdata":
				changed.SealData = []byte{9}
			case "release":
				changed.BadBlockReleased = true
			}
			if _, ok, err := p.take(changed, writer, engine, h); err != nil || ok {
				t.Fatal("different signing question reused", ok, err)
			}
		})
	}
	p := makePool()
	proof, ok, err := p.take(out, "synthetic", 1, head)
	if err != nil || !ok || proof.Source != b || p.origins[proof.Source] != (timedOutputKey{Source: a, Output: 0}) {
		t.Fatal(proof, ok, err)
	}
	if _, ok, err = p.take(out, "synthetic", 1, head); err != nil || ok {
		t.Fatal("signature evidence reused", ok, err)
	}
	p = makePool()
	p.last[answerCoordinate{writer: "synthetic", engine: 1}] = 3
	if _, ok, err = p.take(out, "synthetic", 1, head); err != nil || ok {
		t.Fatal("signing order reversed", ok, err)
	}
}
func TestTimedSigningPoolRejectsConflictingObservedOutcomes(t *testing.T) {
	source := TimedSource{Writer: "synthetic", Engine: 1, Step: 1, Ordinal: 1}
	second := source
	second.Step = 2
	second.Ordinal = 2
	out := consensus.Broadcast{Msg: &codec.Message{Code: codec.CodePrepare}}
	signed := *out.Msg
	signed.Signature = []byte{1}
	payload, err := codec.EncodeMessage(&signed)
	if err != nil {
		t.Fatal(err)
	}
	proofs := map[timedOutputKey]timedSigningEvidence{
		{source, 0}: {out, consensus.Message{Code: signed.Code, Payload: payload}, TimedSource{Writer: "synthetic", Engine: 1, Step: 3, Ordinal: 3}},
		{second, 0}: {out, consensus.BroadcastFailed{Code: signed.Code}, TimedSource{Writer: "synthetic", Engine: 1, Step: 4, Ordinal: 4}},
	}
	entries := map[TimedSource]timedSourceEntry{source: {record: &journal.StepRec{}}, second: {record: &journal.StepRec{}}}
	p, err := newTimedSigningPool(proofs, entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := p.take(out, "synthetic", 1, types.Hash{}); ok || !errors.Is(err, ErrTraceSigningUnavailable) {
		t.Fatal("conflicting outcome selected", ok, err)
	}
}
