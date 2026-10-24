package sim

import (
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// AcceptedCacheProfile requires an explicit diagnostic-only journal choice.
// Its sources compare recorded simulation inputs, not physical I/O or a closed
// runner schedule. Functional cache-policy journal replay remains unavailable.
type AcceptedCacheProfile struct {
	Limits  transport.CachePolicyLimits
	Journal string
}

const CacheDiagnosticOnly = "diagnostic_only"

func cloneAcceptedCache(p *AcceptedCacheProfile, sc Scenario) (*AcceptedCacheProfile, error) {
	if p == nil {
		return nil, nil
	}
	if p.Journal != CacheDiagnosticOnly || p.Limits.Validate() != nil || len(sc.Nodes) != len(sc.Validators) {
		return nil, fmt.Errorf("%w: accepted cache requires valid limits and explicit diagnostic-only journals", ErrScenario)
	}
	for _, n := range sc.Nodes {
		if n.WriteQueue == nil || n.Processing != nil || n.NextHeight != nil {
			return nil, fmt.Errorf("%w: accepted cache requires normal write queues and atomic processing on all endpoints", ErrScenario)
		}
	}
	out := *p
	return &out, nil
}

// cacheSources belongs to one original diagnostic writer, independently of a
// later node incarnation. Only the manual simulation driver calls it.
type cacheSources struct {
	writer     journal.Writer
	clock      *nodeClock
	run        string
	owner      *transport.AttemptOwner
	sequence   uint64
	peers      map[types.Address]uint32
	registered map[uint32]bool
}

func newCacheSources(n *node, writer journal.Writer) *cacheSources {
	f := &cacheSources{writer: writer, clock: n.clock, run: n.runID(), owner: transport.NewAttemptOwner(),
		peers: map[types.Address]uint32{}, registered: map[uint32]bool{}}
	for _, peer := range n.s.nodes {
		f.peers[peer.v.address] = uint32(peer.i)
	}
	return f
}

func (f *cacheSources) peer(addr types.Address) (uint32, bool) {
	idx, known := f.peers[addr]
	if !known {
		return 0, false
	}
	if !f.registered[idx] {
		f.writer.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: idx, Addr: addr, Event: "attached"}})
		f.registered[idx] = true
	}
	return idx, true
}

func (f *cacheSources) AttemptOwner() *transport.AttemptOwner { return f.owner }
func (f *cacheSources) CaptureRun() string                    { return f.run }
func (f *cacheSources) ObserveWriteTransition(t transport.WriteTransition) {
	f.writer.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: t, Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}
func (f *cacheSources) ObserveReceiveTransition(t transport.ReceiveTransition) {
	f.writer.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: t, Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}
func (f *cacheSources) ObserveCoreStep(s runner.CoreStepObservation) {
	f.writer.Put(journal.Record{Body: &s})
}
func (f *cacheSources) ObserveInputSelection(source journal.SelectionRec) {
	f.writer.Put(journal.Record{Body: &source})
}
func (f *cacheSources) ObserveInternalSource(source journal.InternalRec) {
	f.writer.Put(journal.Record{Body: &source})
}
func (f *cacheSources) ObserveInboxSource(source journal.InboxRec) {
	f.writer.Put(journal.Record{Body: &source})
}
func (f *cacheSources) ObserveFinalizeSource(source journal.FinalizeRec) {
	f.writer.Put(journal.Record{Body: &source})
}
func (f *cacheSources) ObserveAppQueueSource(source journal.AppQueueRec) {
	f.writer.Put(journal.Record{Body: &source})
}
func (f *cacheSources) ObserveTimerSource(t journal.TimerRec) {
	if t.Sequence == 0 || t.EngineRun == 0 || len(t.Input) == 0 && t.Action != "clear" && t.Action != "cancel" {
		f.writer.Put(journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindTimer), Count: 1}}, FirstMono: t.Mono, LastMono: t.Mono}})
		return
	}
	f.writer.Put(journal.Record{Body: &t})
}
func cacheSessionRef(s *transport.WriteSession) *journal.SessionRef {
	if s == nil || s.ObservationRun() == "" || s.ObservationID() == 0 {
		return nil
	}
	return &journal.SessionRef{Run: s.ObservationRun(), Ordinal: s.ObservationID()}
}
func (f *cacheSources) session(p transport.WritePeer, kind string) {
	if kind == journal.SessionObserved {
		if _, known := f.peer(p.Addr); !known {
			return
		}
		p.Session.BindObservationRun(f.run)
	}
	f.writer.Put(journal.Record{Body: &journal.SessionRec{Session: cacheSessionRef(p.Session), Peer: p.Addr, Event: kind, Active: p.Session.Active(), Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}})
}
func (f *cacheSources) wrote(p transport.WritePeer, code uint64, payload []byte, a transport.SendAttempt) {
	idx, known := f.peer(p.Addr)
	if !known {
		return
	}
	m := &journal.MsgRec{Dir: journal.Out, PeerIdx: idx, Session: cacheSessionRef(p.Session), Code: code, WireCode: code,
		Payload: append([]byte(nil), payload...), DedupKey: codec.DedupKey(payload), Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano(), Write: "ok"}
	if a.OwnedBy(f.owner) {
		m.Cause = a.Cause
		if s, ok := a.WriteSource(); ok {
			m.WriteAttempt = &journal.WriteAttemptSource{Sequence: a.Sequence, WriterRun: s.WriterRun, Ledger: s.Ledger, Request: s.Request}
		}
	}
	// IO stays nil: the manual model has not measured an actual socket call.
	f.writer.Put(journal.Record{Body: m})
}

func (t *writeAdapter) WriteAttempt(ticket transport.WriteTicket, cause event.SendCause) transport.SendAttempt {
	f := t.n.sources
	if f == nil || f.sequence == ^uint64(0) {
		return transport.SendAttempt{}
	}
	f.sequence++
	return transport.NewWriteSendAttempt(f.owner, f.sequence, ticket, cause)
}
