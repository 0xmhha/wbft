package journal

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// These are primitive cache histories with real signed payloads. They do not
// stand in for the separate actual-core ACCEPT and physical-source tests.
func receiveCheckFixture(t *testing.T, record func(*journalReceiveTransitions, *transport.ReceiveLedger)) []Record {
	t.Helper()
	fs := fsys.NewMem()
	id := ident()
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 64, ReceivePerPeer: 64, WritePending: 64, WritePerPeer: 64}}
	writer, err := Open(Options{FS: fs, Dir: "/receive-check", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalReceiveTransitions{writer: writer, start: time.Now()}
	ledger, err := transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 64, PerPeer: 64, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	record(observer, ledger)
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/receive-check")
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestReceiveCacheCheckNormalLRUEvictionsAndScopes(t *testing.T) {
	records := receiveCheckFixture(t, func(_ *journalReceiveTransitions, ledger *transport.ReceiveLedger) {
		key, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("normal-receive-check-key")))
		if err != nil {
			t.Fatal(err)
		}
		scope := transport.NewValidationScope()
		peer := ecdsa.Address(key)
		var first, last []byte
		for round := uint64(1); round <= uint64(transport.InmemoryMessages)+2; round++ {
			message := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(round)}}
			signed, err := codec.SigningPayload(message, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			message.Signature, err = ecdsa.SignData(signed, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := codec.EncodeMessage(message)
			if err != nil {
				t.Fatal(err)
			}
			if round == 1 {
				first = raw
			}
			last = raw
			origin := transport.ReceiveOrigin{WriterRun: "normal-receive-source", CaptureID: round}
			in := transport.Inbound{Peer: peer, Code: uint64(message.Code), Payload: raw, Capture: round, Origin: origin}
			ticket, decision := ledger.Prepare(scope, in, origin)
			if decision != transport.ReceiveReserved {
				t.Fatal(decision)
			}
			if ledger.Accept(ticket, in) != transport.ReceiveRegistered {
				t.Fatal("full check not retained")
			}
		}
		code := uint64(codec.CodeRoundChange)
		if ledger.Known(scope, code, first) || !ledger.Known(scope, code, last) {
			t.Fatal("known LRU boundary differs")
		}
		otherScope := transport.NewValidationScope()
		var tickets []transport.ReceiveTicket
		var inputs []transport.Inbound
		for index := byte(1); index <= byte(transport.InmemoryPeers)+1; index++ {
			origin := transport.ReceiveOrigin{WriterRun: "normal-receive-source", CaptureID: 2000 + uint64(index)}
			in := transport.Inbound{Peer: types.Address{index}, Code: code, Payload: last, Capture: origin.CaptureID, Origin: origin}
			ticket, decision := ledger.Prepare(otherScope, in, origin)
			if decision != transport.ReceiveReserved {
				t.Fatal("pending copy authenticated another", decision)
			}
			tickets = append(tickets, ticket)
			inputs = append(inputs, in)
		}
		for index, ticket := range tickets {
			expected := transport.ReceiveDuplicate
			if index == 0 {
				expected = transport.ReceiveRegistered
			}
			if ledger.Accept(ticket, inputs[index]) != expected {
				t.Fatal("independent normal copy check differs")
			}
		}
		if ledger.Recent(otherScope, types.Address{1}, code, last) || !ledger.Recent(otherScope, types.Address{byte(transport.InmemoryPeers) + 1}, code, last) {
			t.Fatal("peer recent LRU boundary differs")
		}
		scope.Close()
		otherScope.Close()
		if ledger.Known(scope, code, last) || ledger.Known(otherScope, code, last) {
			t.Fatal("closed context authenticated a lookup")
		}
	})
	check, err := CheckReceiveCacheTransitions(records, ReceiveCacheCheckLimits{Records: 10000, Ledgers: 16, Reordered: 128})
	if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" || check.Ledgers != 1 {
		t.Fatal(check, err)
	}
	t.Logf("signed_payloads=%d pending_normal_copies=%d reconstructed_transitions=%d physical_status=%s", transport.InmemoryMessages+2, transport.InmemoryPeers+1, check.Transitions, check.PhysicalStatus)
}

func TestReceiveCacheCheckMissingAndContradictoryMetadata(t *testing.T) {
	records := receiveCheckFixture(t, func(_ *journalReceiveTransitions, ledger *transport.ReceiveLedger) {
		normal := deferredNormalMessage(t)
		scope := transport.NewValidationScopeWithContext(transport.ValidationContext{Sequence: "11", Round: "1", State: "AcceptRequest", PriorRound: "0"})
		in := transport.Inbound{Peer: normal.Peer, Code: uint64(normal.Code), Payload: normal.Payload}
		first, d := ledger.Prepare(scope, in, transport.ReceiveOrigin{})
		if d != transport.ReceiveReserved {
			t.Fatal(d)
		}
		second, d := ledger.Prepare(scope, in, transport.ReceiveOrigin{})
		if d != transport.ReceiveReserved {
			t.Fatal(d)
		}
		if ledger.Accept(first, in) != transport.ReceiveRegistered || ledger.Accept(second, in) != transport.ReceiveDuplicate {
			t.Fatal("normal full checks missing")
		}
	})
	limits := ReceiveCacheCheckLimits{Records: 1000, Ledgers: 4, Reordered: 16}
	check, err := CheckReceiveCacheTransitions(records, limits)
	if err != nil || check.Status != "consistent" {
		t.Fatal(check, err)
	}
	var missing, contradictory, changedContext []Record
	// Detached metadata snapshots are changed only to test the offline checker.
	// No transport bytes, live source files or acceptance results are injected.
	for _, record := range records {
		contextCopy := record
		if r, ok := record.Body.(*ReceiveCacheRec); ok {
			if r.Transition.Sequence != 2 {
				missing = append(missing, record)
			}
			changed := *r
			changedScope := *r
			if changed.Transition.Decision == transport.ReceiveDuplicate {
				changed.Transition.Known = false
				changed.Transition.Decision = transport.ReceiveRegistered
				changedScope.Transition.Context.Round = "2"
			}
			record.Body = &changed
			contextCopy.Body = &changedScope
		} else {
			missing = append(missing, record)
		}
		contradictory = append(contradictory, record)
		changedContext = append(changedContext, contextCopy)
	}
	check, err = CheckReceiveCacheTransitions(missing, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "missing_transition" {
		t.Fatal("missing checking sequence inferred", check, err)
	}
	check, err = CheckReceiveCacheTransitions(contradictory, limits)
	if !errors.Is(err, ErrReceiveCacheHistory) || check.Status != "inconsistent" {
		t.Fatal("false first-accept claim retained", check, err)
	}
	check, err = CheckReceiveCacheTransitions(changedContext, limits)
	if !errors.Is(err, ErrReceiveCacheHistory) || check.Reason != "scope_context_changed" {
		t.Fatal("original scope rebound", check, err)
	}
	gap := append([]Record(nil), records...)
	gap = append(gap, Record{Body: &GapRec{Dropped: 1, ByKind: []KindCount{{Kind: uint64(KindReceiveCache), Count: 1}}}})
	check, err = CheckReceiveCacheTransitions(gap, limits)
	if err != nil || check.Reason != "receive_cache_gap" {
		t.Fatal("checking gap concealed", check, err)
	}
	check, err = CheckReceiveCacheTransitions(records, ReceiveCacheCheckLimits{})
	if err != nil || check.Reason != "inspection_limits_required" {
		t.Fatal(check, err)
	}
	check, err = CheckReceiveCacheTransitions(records, ReceiveCacheCheckLimits{Records: 1, Ledgers: 1, Reordered: 1})
	if err != nil || check.Reason != "record_limit" {
		t.Fatal(check, err)
	}
}

type delayedReceiveObservation struct {
	writer Writer
	held   *Record
}

func (o *delayedReceiveObservation) Put(record Record) {
	if r, ok := record.Body.(*ReceiveCacheRec); ok && r.Transition.Sequence == 2 {
		copyRecord := record
		o.held = &copyRecord
		return
	}
	o.writer.Put(record)
	if o.held != nil {
		o.writer.Put(*o.held)
		o.held = nil
	}
}
func (o *delayedReceiveObservation) Close() error { return o.writer.Close() }

func TestReceiveCacheCheckDelayedObservationOrder(t *testing.T) {
	records := receiveCheckFixture(t, func(observer *journalReceiveTransitions, ledger *transport.ReceiveLedger) {
		observer.writer = &delayedReceiveObservation{writer: observer.writer}
		normal := deferredNormalMessage(t)
		scope := transport.NewValidationScope()
		in := transport.Inbound{Peer: normal.Peer, Code: uint64(normal.Code), Payload: normal.Payload}
		ticket, d := ledger.Prepare(scope, in, transport.ReceiveOrigin{})
		if d != transport.ReceiveReserved {
			t.Fatal(d)
		}
		if ledger.Known(scope, in.Code, in.Payload) {
			t.Fatal("unverified input authenticated")
		}
		if ledger.Accept(ticket, in) != transport.ReceiveRegistered {
			t.Fatal("normal full check missing")
		}
	})
	var sequences []uint64
	for _, record := range records {
		if r, ok := record.Body.(*ReceiveCacheRec); ok {
			sequences = append(sequences, r.Transition.Sequence)
		}
	}
	if len(sequences) < 3 || sequences[0] != 1 || sequences[1] != 3 || sequences[2] != 2 {
		t.Fatal("normal observation delay not exercised", sequences)
	}
	check, err := CheckReceiveCacheTransitions(records, ReceiveCacheCheckLimits{Records: 1000, Ledgers: 4, Reordered: 1})
	if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" {
		t.Fatal(check, err)
	}
}
