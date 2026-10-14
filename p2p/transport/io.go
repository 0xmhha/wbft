package transport

import (
	"time"

	"github.com/0xmhha/wbft/types"
)

// IOMoment uses the recording observer's clock, including its monotonic origin.
// Wall clock changes are retained; no cross-node clock agreement is implied.
type IOMoment struct {
	Mono   time.Duration
	WallNs int64
}

// IOInterval brackets one transport operation. A write ends at WriteMsg return;
// a read ends after the payload is consumed, before frame validation or Offer.
// Read intervals can include waiting for the next message.
type IOInterval struct{ Start, End IOMoment }

// IOObserver is optional. An adapter samples Moment immediately around its I/O
// operation and reports the interval with the original frame, once. It must not
// substitute the later observer callback timestamp for either endpoint.
type IOObserver interface {
	Moment() IOMoment
	ReceivedIO(peer types.Address, code uint64, size int, payload []byte, offer string, capture uint64, interval IOInterval)
	WroteIO(peer types.Address, code uint64, payload []byte, write string, interval IOInterval)
}

// BeginIO returns no clock evidence for an observer without I/O support.
func BeginIO(o FrameObserver) IOMoment {
	if timed, ok := o.(IOObserver); ok {
		return timed.Moment()
	}
	return IOMoment{}
}

func ReportReceivedIO(o FrameObserver, peer types.Address, code uint64, size int, payload []byte, offer string, capture uint64, interval IOInterval) {
	if timed, ok := o.(IOObserver); ok {
		timed.ReceivedIO(peer, code, size, payload, offer, capture, interval)
		return
	}
	ReportReceived(o, peer, code, size, payload, offer, capture)
}

func ReportWroteIO(o FrameObserver, peer types.Address, code uint64, payload []byte, write string, interval IOInterval) {
	if o == nil {
		return
	}
	if timed, ok := o.(IOObserver); ok {
		timed.WroteIO(peer, code, payload, write, interval)
		return
	}
	o.Wrote(peer, code, payload, write)
}
