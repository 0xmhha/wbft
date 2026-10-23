package inputlog

import (
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func TestDeferredInlineSurvivesWithoutObserver(t *testing.T) {
	raw, err := codec.EncodeMessage(signed(t, &codec.Message{Code: codec.CodeRoundChange, View: view(11, 1)}))
	if err != nil {
		t.Fatal(err)
	}
	m := consensus.Message{Code: codec.CodeRoundChange, Payload: raw, Peer: types.Address{7}, RecvMono: 123}
	for _, origin := range []CaptureOrigin{{}, {Run: "first-writer", Capture: 17}} {
		body, err := EncodeDeferredMessage(m, origin)
		if err != nil {
			t.Fatal(err)
		}
		got, gotOrigin, err := DecodeDeferredMessage(body)
		if err != nil || !reflect.DeepEqual(got, m) || gotOrigin != origin {
			t.Fatalf("round trip: %+v %+v %v", got, gotOrigin, err)
		}
		in, err := Decode(KindDeferredMessage, body, func(uint64) ([]byte, error) { t.Fatal("functional replay consulted capture resolver"); return nil, nil })
		if err != nil || !reflect.DeepEqual(in, m) {
			t.Fatalf("functional decode: %+v %v", in, err)
		}
		if _, err := consensus.Recover(m.Code, got.Payload, nil); err != nil {
			t.Fatal(err)
		}
	}
}
