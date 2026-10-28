package node

import (
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"sync"
)

// sessionFrameRecorder is the separate accepted/completed source recorder.
// Node installs it only for an explicit diagnostic writer. Compatible replay
// remains unavailable. The default frameRecorder stays unchanged.
type sessionFrameRecorder struct {
	*frameRecorder
	run                              string
	coreDeclaration                  *journal.CoreOptions
	runtimeMu                        sync.Mutex
	runtimeEnabled, runtimeExhausted bool
	runtimeLimit, runtimeSequence    uint64
	runtimeLoops                     map[runtimeLoopKey]journal.RuntimeRec
}

var _ transport.SessionObserver = (*sessionFrameRecorder)(nil)
var _ transport.SessionIOObserver = (*sessionFrameRecorder)(nil)
var _ transport.WriteTransitionObserver = (*sessionFrameRecorder)(nil)
var _ transport.ReceiveTransitionObserver = (*sessionFrameRecorder)(nil)

func newSessionFrameRecorder(writer journal.Writer, clock stampClock, offset uint64) *sessionFrameRecorder {
	base := newFrameRecorder(writer, clock, offset)
	rec := &sessionFrameRecorder{frameRecorder: base, run: base.CaptureRun()}
	if writer, ok := writer.(interface{ CoreDeclaration() journal.CoreOptions }); ok {
		declaration := writer.CoreDeclaration().Copy()
		rec.coreDeclaration = &declaration
	}
	return rec
}

func (f *sessionFrameRecorder) CaptureRun() string { return f.run }

func observedSessionRef(target transport.WritePeer) *journal.SessionRef {
	run, ordinal := target.Session.ObservationRun(), target.Session.ObservationID()
	if run == "" || ordinal == 0 {
		return nil
	}
	return &journal.SessionRef{Run: run, Ordinal: ordinal}
}

func (f *sessionFrameRecorder) session(target transport.WritePeer, event string) {
	f.jw.Put(journal.Record{Body: &journal.SessionRec{Session: observedSessionRef(target), Peer: target.Addr, Event: event, Active: target.Session.Active(), Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}
func (f *sessionFrameRecorder) ObservedSession(target transport.WritePeer) {
	target.Session.BindObservationRun(f.CaptureRun())
	f.session(target, journal.SessionObserved)
}
func (f *sessionFrameRecorder) EndedSession(target transport.WritePeer, reason transport.SessionEnd) {
	f.session(target, string(reason))
}
func (f *sessionFrameRecorder) ReceivedSession(target transport.WritePeer, code uint64, size int, payload []byte, offer string, capture uint64, interval *transport.IOInterval) {
	m := f.msg(journal.In, target.Addr, code, append([]byte(nil), payload...))
	m.Session, m.Capture, m.Offer = observedSessionRef(target), capture, offer
	if interval != nil {
		m.IO = recordedIO(*interval)
	}
	if f.engine != nil {
		m.Engine = f.engine()
	}
	// The old read-loop hits map cannot prove accepted-input cache checks.
	if size > len(payload) {
		m.Size = uint64(size)
		m.DedupKey = [32]byte{}
	}
	f.jw.Put(journal.Record{Body: m})
}
func (f *sessionFrameRecorder) WroteSession(target transport.WritePeer, code uint64, payload []byte, write string, attempt transport.SendAttempt, interval *transport.IOInterval) {
	m := f.msg(journal.Out, target.Addr, code, append([]byte(nil), payload...))
	m.Session, m.Write = observedSessionRef(target), write
	if interval != nil {
		m.IO = recordedIO(*interval)
	}
	if attempt.OwnedBy(f.owner) {
		m.Cause = attempt.Cause
		if source, ok := attempt.WriteSource(); ok {
			m.WriteAttempt = &journal.WriteAttemptSource{Sequence: attempt.Sequence, WriterRun: source.WriterRun, Ledger: source.Ledger, Request: source.Request}
		}
	}
	// This profile never consults the legacy cause/hits maps or cache domain.
	f.jw.Put(journal.Record{Body: m})
}
func (f *sessionFrameRecorder) ObserveWriteTransition(event transport.WriteTransition) {
	f.jw.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: event, Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}
func (f *sessionFrameRecorder) ObserveReceiveTransition(event transport.ReceiveTransition) {
	f.jw.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: event, Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}

// recordedWriteTransport adds observation metadata to the optional functional
// sender without acquiring the legacy CacheObserver interface. Queue rejection
// has its actual ledger transition, never an invented physical frame callback.
type recordedWriteTransport struct {
	transport.Transport
	transport.WriteSender
	rec *sessionFrameRecorder
}

var _ transport.WriteAttemptFactory = recordedWriteTransport{}

func (t recordedWriteTransport) WritePeers() []transport.WritePeer {
	targets := t.WriteSender.WritePeers()
	for _, target := range targets {
		// Freeze observation metadata before the original ledger reservation
		// snapshots this exact session. The adapter's original loop still
		// owns the observed-session and I/O callbacks. No origin is invented
		// for a target whose loop never produces an observation.
		target.Session.BindObservationRun(t.rec.CaptureRun())
	}
	return targets
}

func (t recordedWriteTransport) WriteAttempt(ticket transport.WriteTicket, cause event.SendCause) transport.SendAttempt {
	for {
		previous := t.rec.attemptSequence.Load()
		if previous == ^uint64(0) {
			return transport.SendAttempt{}
		}
		if t.rec.attemptSequence.CompareAndSwap(previous, previous+1) {
			return transport.NewWriteSendAttempt(t.rec.owner, previous+1, ticket, cause)
		}
	}
}

var _ runner.CoreStepObserver = (*sessionFrameRecorder)(nil)

func (f *sessionFrameRecorder) ObserveCoreStep(source runner.CoreStepObservation) {
	f.jw.Put(journal.Record{Body: &source})
}
