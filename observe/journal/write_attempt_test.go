package journal

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
)

func TestWriteAttemptReservationDomainAndStrictLocalCodec(t *testing.T) {
	normal := deferredNormalMessage(t)
	m := &MsgRec{Dir: Out, Payload: normal.Payload, Code: uint64(normal.Code), WriteAttempt: &WriteAttemptSource{Sequence: ^uint64(0), WriterRun: "original-writer", Ledger: (1 << 53) + 1, Request: ^uint64(0)}}
	raw, err := encodeBody(Record{Body: m}, 2)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindMsg, raw)
	if err != nil || !reflect.DeepEqual(decoded.Body, m) {
		t.Fatal("exact original reservation changed", decoded, err)
	}
	again, err := encodeBody(decoded, 2)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("source bytes changed", err)
	}
	base := *m
	base.WriteAttempt = nil
	if size(Record{Body: m})-size(Record{Body: &base}) != 64+int64(len(m.WriteAttempt.WriterRun)) {
		t.Fatal("source missing from queue byte budget")
	}
	var wire msgRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// These malformed shapes remain local codec input, never network traffic.
	for _, change := range []func(*msgRLP){
		func(w *msgRLP) { w.Dir = In },
		func(w *msgRLP) { w.Attempt = []uint64{1, 1, 1, 1} },
		func(w *msgRLP) { w.WriteAttempt[0].Profile++ },
		func(w *msgRLP) { w.WriteAttempt[0].Sequence = 0 },
		func(w *msgRLP) { w.WriteAttempt[0].WriterRun = "" },
		func(w *msgRLP) { w.WriteAttempt[0].Ledger = 0 },
		func(w *msgRLP) { w.WriteAttempt[0].Request = 0 },
		func(w *msgRLP) { w.WriteAttempt = append(w.WriteAttempt, w.WriteAttempt[0]) },
	} {
		w := wire
		w.WriteAttempt = append([]writeAttemptRLP(nil), wire.WriteAttempt...)
		change(&w)
		b, err := rlp.Encode(&w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindMsg, b); err == nil {
			t.Fatal("invalid source silently used legacy semantics")
		}
	}
	for _, a := range []*WriteAttemptSource{{}, {Sequence: 1, WriterRun: "run", Ledger: 1}, {Sequence: 1, Ledger: 1, Request: 1}} {
		copy := *m
		copy.WriteAttempt = a
		if _, err := encodeBody(Record{Body: &copy}, 2); err == nil {
			t.Fatal("partial source encoded")
		}
	}
	copy := *m
	copy.Attempt = &SendAttempt{Sequence: 1}
	if _, err := encodeBody(Record{Body: &copy}, 2); err == nil {
		t.Fatal("legacy and completed-write sources mixed")
	}
}
