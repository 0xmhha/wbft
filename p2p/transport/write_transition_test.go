package transport

import (
	"crypto/sha256"
	"slices"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

type writeTransitions struct {
	mu      sync.Mutex
	events  []WriteTransition
	inspect func()
}

func (s *writeTransitions) ObserveWriteTransition(e WriteTransition) {
	// A callback may inspect the ledger because observation is outside its lock.
	if s.inspect != nil {
		s.inspect()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}
func (s *writeTransitions) snapshot() []WriteTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.events)
	slices.SortFunc(out, func(a, b WriteTransition) int {
		if a.Sequence < b.Sequence {
			return -1
		}
		if a.Sequence > b.Sequence {
			return 1
		}
		return 0
	})
	return out
}

func TestWriteSessionObservationNormalLifetimes(t *testing.T) {
	var absent *WriteSession
	if absent.ObservationID() != 0 || new(WriteSession).ObservationID() != 0 {
		t.Fatal("unavailable identity was inferred")
	}
	const count = 128
	observations := make(chan uint64, count)
	var workers sync.WaitGroup
	for range count {
		workers.Go(func() {
			session := NewWriteSession()
			id := session.ObservationID()
			session.Close()
			if session.Active() || id == 0 || session.ObservationID() != id {
				t.Error("normal close changed stream identity")
			}
			observations <- id
		})
	}
	workers.Wait()
	close(observations)
	seen := map[uint64]bool{}
	for id := range observations {
		if seen[id] {
			t.Fatal("normal stream number reused")
		}
		seen[id] = true
	}
}

func TestWriteTransitionsNormalLifecycle(t *testing.T) {
	observer := new(writeTransitions)
	ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 2, PerPeer: 2, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	observer.inspect = func() { _ = ledger.Closed() }
	target := WritePeer{Addr: types.Address{7}, Session: NewWriteSession()}
	code := uint64(codec.CodeRoundChange)
	first, second, third := ledgerNormalMessage(t, 1), ledgerNormalMessage(t, 2), ledgerNormalMessage(t, 3)
	a, decision := ledger.Prepare(target, code, first)
	if decision != WriteReserved {
		t.Fatal(decision)
	}
	if _, d := ledger.Prepare(target, code, first); d != WriteAlreadyPending {
		t.Fatal(d)
	}
	b, decision := ledger.Prepare(target, code, second)
	if decision != WriteReserved {
		t.Fatal(decision)
	}
	if _, d := ledger.Prepare(target, code, third); d != WritePendingFull {
		t.Fatal(d)
	}
	// This ordinary adapter ordering completes before the queue return is seen.
	if !ledger.Complete(a, WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(first), Result: LocalWriteOK}) {
		t.Fatal("successful local completion missing")
	}
	ledger.QueueResult(a, Queued)
	if _, d := ledger.Prepare(target, code, first); d != WriteAlreadyRecent {
		t.Fatal(d)
	}
	target.Session.Close()
	if ledger.Pending() != 0 {
		t.Fatal("ended stream was retained")
	}
	ledger.Complete(b, WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(second), Result: LocalWriteCancelled})
	replacement := WritePeer{Addr: target.Addr, Session: NewWriteSession()}
	if _, d := ledger.Prepare(replacement, code, first); d != WriteAlreadyRecent {
		t.Fatal("completed address cache was lost on normal reconnect", d)
	}
	c, decision := ledger.Prepare(replacement, code, third)
	if decision != WriteReserved {
		t.Fatal(decision)
	}
	if !ledger.RecordAccepted(replacement, code, second) {
		t.Fatal("accepted reception was not registered")
	}
	ledger.Close()
	ledger.Complete(c, WriteReceipt{Target: replacement, Code: code, PayloadSHA256: sha256.Sum256(third), Result: LocalWriteOK})

	events := observer.snapshot()
	pending := map[uint64]WriteIdentity{}
	var sequence, instance uint64
	registered, pruned, early, late := 0, 0, 0, 0
	for _, event := range events {
		sequence++
		if event.Sequence != sequence || event.Ledger == 0 {
			t.Fatal("observation gap", event)
		}
		if instance == 0 {
			instance = event.Ledger
		}
		if event.Ledger != instance {
			t.Fatal("ledger owner changed")
		}
		if event.PendingBefore != uint64(len(pending)) {
			t.Fatal("pending prefix differs before operation", event)
		}
		for _, request := range event.Pruned {
			if _, ok := pending[request]; !ok {
				t.Fatal("unknown closed-stream request")
			}
			delete(pending, request)
			pruned++
		}
		switch event.Action {
		case WriteStart:
			if sequence != 1 || event.PendingLimit != 2 || event.PerPeerLimit != 2 || !event.KeyWithCode {
				t.Fatal(event)
			}
		case WritePrepare:
			if event.Input.Session == 0 || event.Input.Key == (types.Hash{}) || event.Input.PayloadSHA256 == (types.Hash{}) {
				t.Fatal("normal metadata missing")
			}
			if event.Decision == WriteReserved {
				if event.Request != event.Sequence || pending[event.Request] != (WriteIdentity{}) {
					t.Fatal("request was reused")
				}
				pending[event.Request] = event.Input
			}
		case WriteComplete:
			_, owned := pending[event.Request]
			if event.Owned != owned {
				t.Fatal("terminal ownership differs", event)
			}
			if event.Released {
				delete(pending, event.Request)
			}
			if event.Registered {
				if !owned || !event.Matched || !event.Valid || event.Result != LocalWriteOK || !event.SessionActive || event.Closed {
					t.Fatal("incomplete local write was registered", event)
				}
				registered++
			} else if !owned {
				late++
			}
		case WriteQueueResult:
			if event.Queue == Queued && !event.Owned {
				early++
			}
			if event.Released {
				delete(pending, event.Request)
			}
		case WriteAccept:
			if !event.Registered || !event.SessionActive || !event.Valid {
				t.Fatal(event)
			}
			registered++
		case WriteClose:
			clear(pending)
		case WritePrune:
		default:
			t.Fatal("unknown actual action", event.Action)
		}
		if event.PendingAfter != uint64(len(pending)) {
			t.Fatal("pending prefix differs after operation", event)
		}
	}
	if registered != 2 || pruned != 1 || early != 1 || late != 2 {
		t.Fatal("normal lifecycle coverage changed", registered, pruned, early, late)
	}
}

func TestWriteTransitionsConcurrentNormalCompletions(t *testing.T) {
	observer := new(writeTransitions)
	ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 64, PerPeer: 64, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	observer.inspect = func() { _ = ledger.Closed() }
	target := WritePeer{Addr: types.Address{7}, Session: NewWriteSession()}
	code := uint64(codec.CodeRoundChange)
	var workers sync.WaitGroup
	for round := uint64(1); round <= 64; round++ {
		raw := ledgerNormalMessage(t, round)
		ticket, decision := ledger.Prepare(target, code, raw)
		if decision != WriteReserved {
			t.Fatal(decision)
		}
		workers.Go(func() {
			if !ledger.Complete(ticket, WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(raw), Result: LocalWriteOK}) {
				t.Error("normal completion lost")
			}
			ledger.QueueResult(ticket, Queued)
		})
	}
	workers.Wait()
	if ledger.Pending() != 0 {
		t.Fatal("pending normal writes leaked")
	}
	events := observer.snapshot()
	completions := 0
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatal("mutex order is not recoverable")
		}
		if event.Action == WriteComplete && event.Registered {
			completions++
		}
	}
	if completions != 64 {
		t.Fatal(completions)
	}
}

func TestWriteTransitionsClosedRequestSetHasCanonicalOrder(t *testing.T) {
	observer := new(writeTransitions)
	ledger, err := NewWriteLedger(WriteLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	raw := ledgerNormalMessage(t, 1)
	var sessions []*WriteSession
	for i := byte(1); i <= 4; i++ {
		target := WritePeer{Addr: types.Address{i}, Session: NewWriteSession()}
		if _, d := ledger.Prepare(target, uint64(codec.CodeRoundChange), raw); d != WriteReserved {
			t.Fatal(d)
		}
		sessions = append(sessions, target.Session)
	}
	for _, session := range sessions {
		session.Close()
	}
	if ledger.Pending() != 0 {
		t.Fatal("normally closed requests retained")
	}
	events := observer.snapshot()
	last := events[len(events)-1]
	if last.Action != WritePrune || len(last.Pruned) != 4 || !slices.IsSorted(last.Pruned) {
		t.Fatal("closed request set depends on map iteration", last.Pruned)
	}
	ledger.Close()
}
