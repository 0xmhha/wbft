package transport

// SessionLoop identifies an original adapter loop. A functional session ending
// does not establish that any of these loops has returned.
type SessionLoop string

const (
	SessionReaderLoop   SessionLoop = "reader"
	SessionWriterLoop   SessionLoop = "writer"
	SessionProtocolLoop SessionLoop = "protocol"
)

type SessionLoopPhase string

const (
	SessionLoopEntered  SessionLoopPhase = "enter"
	SessionLoopReturned SessionLoopPhase = "return"
)

// SessionLoopObserver receives original loop boundaries outside adapter locks.
// Its observer and exact original session are frozen at protocol entry. It must
// return promptly. This contract does not imply remote delivery or persistence.
type SessionLoopObserver interface {
	ObserveSessionLoop(WritePeer, SessionLoop, SessionLoopPhase)
}

func ReportSessionLoop(observer FrameObserver, target WritePeer, loop SessionLoop, phase SessionLoopPhase) {
	if source, ok := observer.(SessionLoopObserver); ok {
		source.ObserveSessionLoop(target, loop, phase)
	}
}
