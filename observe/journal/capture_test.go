package journal

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestCaptureIndexFindsLateRecordAndRejectsDuplicate(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		fs := fsys.NewMem()
		w, err := Open(Options{FS: fs, Dir: "/j", Synchronous: true}, ident())
		if err != nil {
			t.Fatal(err)
		}
		w.Put(Record{Body: &PeerRec{PeerIdx: 2, Addr: types.Address{2}, Event: "attached"}})
		w.Put(Record{Body: step(1)}) // an asynchronous observer may record its frame later
		msg := &MsgRec{Capture: 37, Dir: In, PeerIdx: 2, Code: 0x13, Payload: []byte{0xc0}}
		w.Put(Record{Body: msg})
		if duplicate {
			w.Put(Record{Body: msg})
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := OpenReader(fs, "/j")
		if err != nil {
			t.Fatal(err)
		}
		frame, err := r.ResolveCapture("run-1", 37)
		if duplicate {
			if !errors.Is(err, ErrCapture) {
				t.Fatal("duplicate accepted", err)
			}
		} else if err != nil || frame.Peer != types.Address([20]byte{2}) || frame.Record.Capture != 37 {
			t.Fatal(frame, err)
		}
		if _, err = r.ResolveCapture("run-1", 38); !errors.Is(err, ErrCaptureMissing) {
			t.Fatal(err)
		}
		if _, err = r.ResolveCapture("another-run", 37); !errors.Is(err, ErrCaptureMissing) {
			t.Fatal("cross-run capture", err)
		}
	}
}
func TestMessageBeforeCaptureExtensionStillDecodes(t *testing.T) {
	old := msgRLPNoCapture{Format: Format, JSeq: 7, Dir: In, PeerIdx: 3, Code: 0x13, Payload: []byte{0xc0}, Dedup: 1}
	raw, err := rlp.Encode(&old)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeBody(KindMsg, raw)
	if err != nil {
		t.Fatal(err)
	}
	m := record.Body.(*MsgRec)
	if m.Capture != 0 || record.JSeq != 7 || m.PeerIdx != 3 || m.Dedup == nil {
		t.Fatal(record)
	}
}
