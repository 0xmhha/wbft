package journal

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
)

const DeferredInputProfile uint64 = 1

// DeferredOptions declares the receive-lane profile independently of the pure
// consensus flags. Absence preserves the original journal bytes and behavior.
type DeferredOptions struct {
	Profile   uint64 `json:"profile"`
	Entries   uint64 `json:"entries"`
	Bytes     uint64 `json:"bytes"`
	PerPeer   uint64 `json:"per_peer"`
	PerSource uint64 `json:"per_source"`
}

func (o *DeferredOptions) Validate() error {
	if o != nil && (o.Profile != DeferredInputProfile || o.Entries == 0 || o.Bytes == 0 || o.PerPeer == 0 || o.PerSource == 0) {
		return fmt.Errorf("journal: unsupported deferred receive profile")
	}
	return nil
}

func (o *DeferredOptions) encode() []uint64 {
	if o == nil {
		return nil
	}
	return []uint64{o.Profile, o.Entries, o.Bytes, o.PerPeer, o.PerSource}
}

func decodeDeferredOptions(raw []uint64) (*DeferredOptions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != 5 {
		return nil, fmt.Errorf("journal: deferred profile field count")
	}
	// Preserve an unknown profile for explicit capability validation by the
	// consumer; decoding a segment is not an acceptance of its behavior.
	return &DeferredOptions{Profile: raw[0], Entries: raw[1], Bytes: raw[2], PerPeer: raw[3], PerSource: raw[4]}, nil
}

// DeferredEvidence reports physical provenance separately from functional
// replay. ReceiptMono belongs to Origin.Run; it is not a cross-run clock bridge.
type DeferredEvidence struct {
	Origin      inputlog.CaptureOrigin `json:"origin"`
	Status      string                 `json:"status"`
	Reason      string                 `json:"reason,omitempty"`
	ReceiptMono *string                `json:"receipt_mono_ns,omitempty"`
}

type CaptureResolver interface {
	ResolveCapture(run string, id uint64) (CapturedFrame, error)
}

// InspectDeferred resolves only the exact original writer/capture pair. Missing
// or pruned capture bytes cannot be replaced by a matching packet in another
// run. An unavailable physical source does not reject the inline core input.
func InspectDeferred(reader CaptureResolver, body []byte) (consensus.Message, *DeferredEvidence, error) {
	m, origin, err := inputlog.DecodeDeferredMessage(body)
	if err != nil {
		return m, nil, err
	}
	e := &DeferredEvidence{Origin: origin, Status: "unavailable", Reason: "missing_origin"}
	if origin.Run == "" {
		return m, e, nil
	}
	if reader == nil {
		e.Reason = "capture_resolver_unavailable"
		return m, e, nil
	}
	frame, err := reader.ResolveCapture(origin.Run, origin.Capture)
	if err != nil {
		e.Reason = "capture_unavailable"
		if errors.Is(err, ErrCaptureMissing) {
			e.Reason = "missing_capture"
		}
		return m, e, nil
	}
	if frame.Record == nil {
		e.Reason = "capture_unavailable"
		return m, e, nil
	}
	payload, code, action, _ := transport.DecodeFrame(frame.Record.Code, frame.Record.Payload)
	if frame.Record.Dir != In || frame.Record.Capture != origin.Capture || frame.Record.Size > uint64(len(frame.Record.Payload)) || frame.Record.Offer != transport.OfferQueued || action != transport.FrameDeliver || uint64(m.Code) != code || m.Peer != frame.Peer || !bytes.Equal(m.Payload, payload) {
		e.Reason = "capture_identity"
		return m, e, nil
	}
	mono := strconv.FormatInt(int64(frame.Record.Mono), 10)
	e.Status, e.Reason, e.ReceiptMono = "verified", "", &mono
	return m, e, nil
}
