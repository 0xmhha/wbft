package journal

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	"testing"
)

func TestSendAttemptTailAndLegacyBytes(t *testing.T) {
	// This fixed message body predates both optional tails. It must stay exact.
	legacy := &MsgRec{Dir: Out, Code: 0x13, Payload: []byte{0xc0}}
	raw, err := encodeBody(Record{Body: legacy}, 17)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindMsg, raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeBody(decoded, 17)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("legacy bytes changed", err)
	}
	msg := *legacy
	msg.Attempt = &SendAttempt{Sequence: 9, Cache: 2, Operation: 6}
	raw, err = encodeBody(Record{Body: &msg}, 18)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = decodeBody(KindMsg, raw)
	if err != nil {
		t.Fatal(err)
	}
	if a := decoded.Body.(*MsgRec).Attempt; a == nil || *a != *msg.Attempt {
		t.Fatal("attempt lost", a)
	}
	var wire msgRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, tail := range [][]uint64{{0, 1, 0, 0}, {1, 0, 0, 0}, {1, 1, 0, 3}, {1, 1, 3, 0}, {1, 1}, {1, 1, 0, 0, 0}} {
		wire.Attempt = tail
		b, err := rlp.Encode(&wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindMsg, b); err == nil {
			t.Fatal("malformed attempt accepted", tail)
		}
	}
	for _, a := range []*SendAttempt{{}, {Sequence: 1, Cache: 2}, {Sequence: 1, Operation: 2}} {
		msg.Attempt = a
		if _, err := encodeBody(Record{Body: &msg}, 18); err == nil {
			t.Fatal("invalid attempt encoded", a)
		}
	}
}
