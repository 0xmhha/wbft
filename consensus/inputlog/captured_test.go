package inputlog

import (
	"bytes"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
	"testing"
	"time"
)

func TestCapturedEncodingNeverStoresPayload(t *testing.T) {
	m := consensus.Message{Code: codec.CodePrepare, Payload: []byte("synthetic received bytes"), Peer: types.Address{1}, RecvMono: 123 * time.Nanosecond}
	b, err := EncodeCapturedMessage(m, 18446744073709551615)
	if err != nil || bytes.Contains(b, m.Payload) {
		t.Fatal(b, err)
	}
	ref, err := CapturedReference(b)
	if err != nil || ref != 18446744073709551615 {
		t.Fatal(ref, err)
	}
	decoded, err := Decode(KindCapturedMessage, b, func(id uint64) ([]byte, error) {
		if id != ref {
			t.Fatal(id)
		}
		return m.Payload, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.(consensus.Message)
	if !bytes.Equal(got.Payload, m.Payload) || got.Peer != m.Peer || got.RecvMono != m.RecvMono {
		t.Fatal(got)
	}
	if _, err = Decode(KindCapturedMessage, b, nil); err == nil {
		t.Fatal("missing capture resolver accepted")
	}
	if _, err = EncodeCapturedMessage(m, 0); err == nil {
		t.Fatal("zero identifier accepted")
	}
}
