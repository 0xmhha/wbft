package transport

import (
	"slices"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

type receiveTransitions struct {
	mu      sync.Mutex
	events  []ReceiveTransition
	inspect func()
}

func (o *receiveTransitions) ObserveReceiveTransition(event ReceiveTransition) {
	if o.inspect != nil {
		o.inspect()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}
func (o *receiveTransitions) snapshot() []ReceiveTransition {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := slices.Clone(o.events)
	slices.SortFunc(out, func(a, b ReceiveTransition) int {
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

func TestReceiveTransitionsNormalCheckingLifetimes(t *testing.T) {
	observer := new(receiveTransitions)
	ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 2, PerPeer: 2, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	observer.inspect = func() { _ = ledger.Closed() }
	scope := NewValidationScope()
	secondScope := NewValidationScope()
	if scope.ObservationID() == 0 || scope.ObservationID() == secondScope.ObservationID() {
		t.Fatal("checking scope identity reused")
	}
	raw := ledgerNormalMessage(t, 1)
	later := ledgerNormalMessage(t, 2)
	in := Inbound{Peer: types.Address{7}, Code: uint64(codec.CodeRoundChange), Payload: raw, Capture: 7, Stream: NewWriteSession(), Origin: ReceiveOrigin{WriterRun: "original-check", CaptureID: 7}}
	a, d := ledger.Prepare(scope, in, in.Origin)
	if d != ReceiveReserved {
		t.Fatal(d)
	}
	duplicate := in
	duplicate.Capture = 8
	duplicate.Origin.CaptureID = 8
	b, d := ledger.Prepare(scope, duplicate, duplicate.Origin)
	if d != ReceiveReserved {
		t.Fatal("unverified pending copy authenticated another", d)
	}
	future := in
	future.Payload = later
	if _, d := ledger.Prepare(scope, future, future.Origin); d != ReceivePendingFull {
		t.Fatal(d)
	}
	if ledger.Known(scope, in.Code, raw) || ledger.Recent(scope, in.Peer, in.Code, raw) {
		t.Fatal("unverified bytes became known")
	}
	if ledger.Accept(a, in) != ReceiveRegistered {
		t.Fatal("fully checked input not registered without source observer authority")
	}
	if ledger.AcceptWithSource(b, duplicate, ReceiveAcceptSource{EngineRun: 1, Step: 4, Output: 2, Via: "direct"}) != ReceiveDuplicate {
		t.Fatal("fully checked normal second copy not recorded")
	}
	if !ledger.Known(scope, in.Code, raw) || !ledger.Recent(scope, in.Peer, in.Code, raw) {
		t.Fatal("fully checked bytes missing")
	}
	c, d := ledger.Prepare(scope, future, future.Origin)
	if d != ReceiveReserved {
		t.Fatal(d)
	}
	scopeID := scope.ObservationID()
	scope.Close()
	if scope.ObservationID() != scopeID || ledger.Known(scope, in.Code, raw) {
		t.Fatal("closed scope identity or checking status changed")
	}
	if ledger.Pending() != 0 {
		t.Fatal("ended context retained pending")
	}
	if ledger.Accept(c, future) != ReceiveUnavailable {
		t.Fatal("late old check acquired replacement ownership")
	}
	replacement, d := ledger.Prepare(secondScope, in, in.Origin)
	if d != ReceiveReserved {
		t.Fatal("new checking context inherited old known", d)
	}
	ledger.Cancel(replacement)
	ledger.Close()

	pending := map[uint64]ReceiveTransition{}
	known := map[[2]uint64]bool{}
	registered, duplicates, pruned, late := 0, 0, 0, 0
	events := observer.snapshot()
	for index, event := range events {
		if event.Sequence != uint64(index+1) || event.Ledger == 0 {
			t.Fatal("checking observation sequence missing")
		}
		if event.PendingBefore != uint64(len(pending)) {
			t.Fatal("checking pending prefix differs", event)
		}
		for _, request := range event.Pruned {
			if _, ok := pending[request]; !ok {
				t.Fatal("unknown pruned request")
			}
			delete(pending, request)
			pruned++
		}
		switch event.Action {
		case ReceiveCheckPrepare:
			if event.Decision == ReceiveReserved {
				if event.Request != event.Sequence {
					t.Fatal("request identity inferred")
				}
				pending[event.Request] = event
			}
		case ReceiveCheckAccept:
			original, owned := pending[event.Request]
			if event.Owned != owned {
				t.Fatal("checking ownership differs", event)
			}
			if owned {
				if event.Input != original.Input || event.Origin != original.Origin {
					t.Fatal("checking origin changed")
				}
			} else {
				late++
			}
			if event.Released {
				delete(pending, event.Request)
			}
			if event.Decision == ReceiveRegistered || event.Decision == ReceiveDuplicate {
				// Only the first normal payload is accepted in this fixture.
				key := [2]uint64{event.Scope, event.Input.Code}
				if event.Known != known[key] || !event.Matched || !event.ScopeActive || !event.Recent || event.Closed {
					t.Fatal("unchecked input registered", event)
				}
				if event.Input != event.Checked || event.Origin != event.CheckedOrigin {
					t.Fatal("accepted bytes or capture changed")
				}
				if known[key] {
					duplicates++
				} else {
					registered++
				}
				known[key] = true
			}
		case ReceiveCheckCancel:
			if event.Released {
				delete(pending, event.Request)
			}
		case ReceiveLedgerClose:
			clear(pending)
		case ReceiveLedgerStart, ReceiveKnownInspect, ReceiveRecentInspect, ReceivePendingPrune:
		default:
			t.Fatal("unknown checking action")
		}
		if event.PendingAfter != uint64(len(pending)) {
			t.Fatal("checking pending prefix differs after operation", event)
		}
	}
	if registered != 1 || duplicates != 1 || pruned != 1 || late != 1 {
		t.Fatal("normal checking lifetime coverage changed", registered, duplicates, pruned, late)
	}
}

func TestReceiveTransitionsClosedRequestSetHasCanonicalOrder(t *testing.T) {
	observer := new(receiveTransitions)
	ledger, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	in := Inbound{Peer: types.Address{7}, Code: uint64(codec.CodeRoundChange), Payload: ledgerNormalMessage(t, 1)}
	var scopes []*ValidationScope
	for range 4 {
		scope := NewValidationScope()
		if _, d := ledger.Prepare(scope, in, ReceiveOrigin{}); d != ReceiveReserved {
			t.Fatal(d)
		}
		scopes = append(scopes, scope)
	}
	for _, scope := range scopes {
		scope.Close()
	}
	if ledger.Pending() != 0 {
		t.Fatal("normally closed checks retained")
	}
	events := observer.snapshot()
	last := events[len(events)-1]
	if last.Action != ReceivePendingPrune || len(last.Pruned) != 4 || !slices.IsSorted(last.Pruned) {
		t.Fatal("closed check set depends on map iteration", last.Pruned)
	}
	ledger.Close()
}
