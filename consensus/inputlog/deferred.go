package inputlog

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// KindDeferredMessage is a journal-only, inline input with an optional original
// capture identity. Functional replay never requires the original capture.
const KindDeferredMessage = "deferred_message"

const DeferredMessageFormat uint64 = 1

// CaptureOrigin identifies a frame in its original writer run. A zero pair
// means that physical provenance is unavailable; it does not invalidate the
// inline functional input. It is not a claim that the frame was persisted.
type CaptureOrigin struct {
	Run     string `json:"writer_run"`
	Capture uint64 `json:"capture_id,string"`
}

type deferredRLP struct {
	Format   uint64
	Code     uint64
	Payload  []byte
	Peer     types.Address
	RecvMono uint64
	Run      string
	Capture  uint64
}

// EncodeDeferredMessage keeps the first source identity beside owned inline
// bytes. An incomplete identity is normalized to unavailable, independently of
// functional acceptance. It never rebinds a capture to the current writer.
func EncodeDeferredMessage(m consensus.Message, origin CaptureOrigin) ([]byte, error) {
	if origin.Run == "" || origin.Capture == 0 {
		origin = CaptureOrigin{}
	}
	return rlp.Encode(deferredRLP{Format: DeferredMessageFormat, Code: uint64(m.Code), Payload: bytesOrEmpty(m.Payload), Peer: m.Peer, RecvMono: uint64(m.RecvMono), Run: origin.Run, Capture: origin.Capture})
}

// DecodeDeferredMessage decodes the functional input without consulting an
// observer. Consumers must separately resolve origin before physical analysis.
func DecodeDeferredMessage(body []byte) (consensus.Message, CaptureOrigin, error) {
	var w deferredRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return consensus.Message{}, CaptureOrigin{}, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if w.Format != DeferredMessageFormat || (w.Run == "") != (w.Capture == 0) {
		return consensus.Message{}, CaptureOrigin{}, fmt.Errorf("%w: deferred input version or origin", ErrDecode)
	}
	return consensus.Message{Code: codec.Code(w.Code), Payload: w.Payload, Peer: w.Peer, RecvMono: time.Duration(w.RecvMono)}, CaptureOrigin{Run: w.Run, Capture: w.Capture}, nil
}
