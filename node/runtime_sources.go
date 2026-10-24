package node

import (
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type runtimeLoopKey struct {
	run     string
	session uint64
	peer    types.Address
	loop    transport.SessionLoop
}

var _ transport.SessionLoopObserver = (*sessionFrameRecorder)(nil)

// runtimeRecord runs under the diagnostic-only mutex. It never grants a live
// owner or changes a functional return. Exhaustion emits one classified gap.
func (f *sessionFrameRecorder) runtimeRecord(r journal.RuntimeRec) journal.RuntimeRec {
	if !f.runtimeEnabled {
		return journal.RuntimeRec{}
	}
	if f.runtimeSequence >= f.runtimeLimit || f.runtimeSequence == ^uint64(0) {
		if !f.runtimeExhausted {
			f.runtimeExhausted = true
			mono := f.clock.Mono()
			f.jw.Put(journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindRuntime), Count: 1}}, FirstMono: mono, LastMono: mono}})
		}
		return journal.RuntimeRec{}
	}
	f.runtimeSequence++
	r.Version, r.Namespace, r.Sequence = journal.RuntimeSourceVersion, f.run, f.runtimeSequence
	if r.Phase == "enter" {
		r.Request = r.Sequence
	}
	r.Mono, r.WallNs = uint64(f.clock.Mono()), uint64(f.clock.Now().UnixNano())
	f.jw.Put(journal.Record{Body: &r})
	return r
}

func (f *sessionFrameRecorder) ObserveSessionLoop(target transport.WritePeer, loop transport.SessionLoop, phase transport.SessionLoopPhase) {
	if !f.runtimeEnabled {
		return
	}
	f.runtimeMu.Lock()
	defer f.runtimeMu.Unlock()
	ref := observedSessionRef(target)
	r := journal.RuntimeRec{Component: journal.RuntimeComponent(loop), Phase: string(phase), Peer: target.Addr}
	if ref != nil {
		r.SessionRun, r.Session = ref.Run, ref.Ordinal
	}
	if r.SessionRun != f.run || r.Session == 0 {
		r.Unavailable = "session_unqualified"
	}
	key := runtimeLoopKey{r.SessionRun, r.Session, target.Addr, loop}
	if phase == transport.SessionLoopEntered {
		if f.runtimeLoops == nil {
			f.runtimeLoops = map[runtimeLoopKey]journal.RuntimeRec{}
		}
		if _, exists := f.runtimeLoops[key]; exists {
			r.Unavailable = "loop_entry_repeated"
		}
		entered := f.runtimeRecord(r)
		if entered.Sequence != 0 {
			f.runtimeLoops[key] = entered
		}
		return
	}
	if phase != transport.SessionLoopReturned {
		return
	}
	entered, found := f.runtimeLoops[key]
	delete(f.runtimeLoops, key)
	r.Request, r.Result = entered.Request, "returned"
	if !found {
		r.Unavailable = "loop_entry_missing"
	}
	f.runtimeRecord(r)
}

// ObserveRuntimeCall begins observation immediately before an original stop or
// close call. Its returned callback must run once after that same call returns.
// This is a source observer, not a runtime certificate. The caller owns its
// writer; Node.Stop does not stop the application's transport or close its DB.
func (n *Node) ObserveRuntimeCall(component journal.RuntimeComponent) func(error) {
	n.mu.Lock()
	f := n.diagnostic
	n.mu.Unlock()
	if f == nil || !f.runtimeEnabled {
		return func(error) {}
	}
	f.runtimeMu.Lock()
	entered := f.runtimeRecord(journal.RuntimeRec{Component: component, Phase: "enter"})
	f.runtimeMu.Unlock()
	return func(err error) {
		if entered.Sequence == 0 {
			return
		}
		returned := entered
		returned.Phase, returned.Result = "return", "ok"
		if err != nil {
			returned.Result = "error"
		}
		f.runtimeMu.Lock()
		f.runtimeRecord(returned)
		f.runtimeMu.Unlock()
	}
}
