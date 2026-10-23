package transport

// SessionEnd identifies which adapter lifetime ended functional write access.
// It is not a remote-delivery or remote-disconnection claim.
type SessionEnd string

const (
	SessionWriterEnded SessionEnd = "writer_end"
	SessionRemoved     SessionEnd = "stream_removed"
)

// SessionObserver records exact original session objects. ObservedSession
// registers an existing lifetime with this observer; it does not reconstruct
// its original attach time. EndedSession follows functional cancellation and
// runs outside adapter locks. Implementations must return promptly.
type SessionObserver interface {
	ObservedSession(WritePeer)
	EndedSession(WritePeer, SessionEnd)
}

// SessionIOObserver receives actual frame callbacks with their original loop's
// session. A nil interval or zero attempt retains unavailable provenance. Its
// callbacks replace the corresponding legacy frame callback, never duplicate
// one. The session pointer is process-local metadata and must not be serialized.
type SessionIOObserver interface {
	ReceivedSession(WritePeer, uint64, int, []byte, string, uint64, *IOInterval)
	WroteSession(WritePeer, uint64, []byte, string, SendAttempt, *IOInterval)
}

func ReportSessionEnded(observer FrameObserver, target WritePeer, reason SessionEnd) {
	if source, ok := observer.(SessionObserver); ok {
		source.EndedSession(target, reason)
	}
}
func ReportSessionReceived(observer FrameObserver, target WritePeer, code uint64, size int, payload []byte, offer string, capture uint64, interval *IOInterval) {
	if source, ok := observer.(SessionIOObserver); ok {
		source.ReceivedSession(target, code, size, payload, offer, capture, interval)
		return
	}
	if interval != nil {
		ReportReceivedIO(observer, target.Addr, code, size, payload, offer, capture, *interval)
	} else {
		ReportReceived(observer, target.Addr, code, size, payload, offer, capture)
	}
}
func ReportSessionWrote(observer FrameObserver, target WritePeer, code uint64, payload []byte, result string, attempt SendAttempt, interval *IOInterval) {
	if source, ok := observer.(SessionIOObserver); ok {
		source.WroteSession(target, code, payload, result, BindAttempt(observer, attempt), interval)
		return
	}
	ReportWroteAttempt(observer, target.Addr, code, payload, result, attempt, interval)
}
