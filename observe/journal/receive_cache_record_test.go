package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
)

type journalReceiveTransitions struct {
	writer Writer
	start  time.Time
	count  uint64
}

func (o *journalReceiveTransitions) ObserveReceiveTransition(event transport.ReceiveTransition) {
	now := time.Now()
	o.count++
	o.writer.Put(Record{Body: &ReceiveCacheRec{Transition: event, Mono: now.Sub(o.start), WallNs: now.UnixNano()}})
}

func TestReceiveCacheRecordActualCheckingLifecycle(t *testing.T) {
	fs := fsys.NewMem()
	id := ident()
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}}
	writer, err := Open(Options{FS: fs, Dir: "/receive-cache", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalReceiveTransitions{writer: writer, start: time.Now()}
	ledger, err := transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	normal := deferredNormalMessage(t)
	scope := transport.NewValidationScope()
	origin := transport.ReceiveOrigin{WriterRun: "original-receive-capture", CaptureID: (1 << 53) + 1}
	in := transport.Inbound{Peer: normal.Peer, Code: uint64(normal.Code), Payload: normal.Payload, Capture: origin.CaptureID, Origin: origin, Stream: transport.NewWriteSession()}
	first, d := ledger.Prepare(scope, in, origin)
	if d != transport.ReceiveReserved {
		t.Fatal(d)
	}
	second, d := ledger.Prepare(scope, in, origin)
	if d != transport.ReceiveReserved {
		t.Fatal("unchecked copy suppressed another", d)
	}
	if ledger.Known(scope, in.Code, in.Payload) || ledger.Recent(scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("unchecked bytes became known")
	}
	if ledger.Accept(first, in) != transport.ReceiveRegistered {
		t.Fatal("normal full check not registered")
	}
	source := transport.ReceiveAcceptSource{EngineRun: 1, Step: (1 << 53) + 1, Output: 3, Via: "direct"}
	if ledger.AcceptWithSource(second, in, source) != transport.ReceiveDuplicate {
		t.Fatal("normal fully checked duplicate missing")
	}
	if !ledger.Known(scope, in.Code, in.Payload) || !ledger.Recent(scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("accepted bytes missing")
	}
	scope.Close()
	if ledger.Known(scope, in.Code, in.Payload) || ledger.Recent(scope, in.Peer, in.Code, in.Payload) {
		t.Fatal("closed context authenticated a lookup")
	}
	nextScope := transport.NewValidationScope()
	pending, d := ledger.Prepare(nextScope, in, origin)
	if d != transport.ReceiveReserved {
		t.Fatal("new context inherited old acceptance", d)
	}
	nextScope.Close()
	if ledger.Pending() != 0 {
		t.Fatal("closed check pending retained")
	}
	if ledger.Accept(pending, in) != transport.ReceiveUnavailable {
		t.Fatal("late old check registered")
	}
	ledger.Cancel(pending)
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/receive-cache")
	if err != nil {
		t.Fatal(err)
	}
	check, err := CheckReceiveCacheTransitions(records, ReceiveCacheCheckLimits{Records: 10000, Ledgers: 16, Reordered: 128})
	if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" {
		t.Fatal("actual checking trace reconstruction", check, err)
	}
	count := uint64(0)
	accepted := 0
	withSource := 0
	for _, record := range records {
		r, ok := record.Body.(*ReceiveCacheRec)
		if !ok {
			continue
		}
		count++
		if record.Kind != KindReceiveCache || r.Transition.Sequence != count {
			t.Fatal("receive ledger ordering lost")
		}
		raw, err := encodeBody(record, record.JSeq)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindReceiveCache, raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := encodeBody(decoded, record.JSeq)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("receive cache metadata bytes changed", err)
		}
		if r.Transition.Decision == transport.ReceiveRegistered || r.Transition.Decision == transport.ReceiveDuplicate {
			accepted++
			if r.Transition.Origin != origin || r.Transition.CheckedOrigin != origin {
				t.Fatal("original capture changed")
			}
			if r.Transition.Source != (transport.ReceiveAcceptSource{}) {
				withSource++
				if r.Transition.Source != source {
					t.Fatal("large source coordinate lost")
				}
			}
		}
	}
	if count != observer.count || accepted != 2 || withSource != 1 {
		t.Fatal("actual receive observations missing", count, observer.count, accepted, withSource)
	}
}

func TestReceiveCacheRecordStrictMetadata(t *testing.T) {
	declaration := &ReceiveCacheRec{Transition: transport.ReceiveTransition{Ledger: ^uint64(0), Sequence: 1, Action: transport.ReceiveLedgerStart, PendingLimit: ^uint64(0), PerPeerLimit: (1 << 53) + 1, KeyWithCode: true}}
	raw, err := encodeBody(Record{Body: declaration}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindReceiveCache, raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.JSeq != ^uint64(0) || decoded.Body.(*ReceiveCacheRec).Transition.PerPeerLimit != (1<<53)+1 {
		t.Fatal("large receive limit lost")
	}
	var wire receiveCacheRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// These are detached metadata codec inputs, never changed transport frames.
	for _, change := range []func(*receiveCacheRLP){
		func(w *receiveCacheRLP) { w.Format++ }, func(w *receiveCacheRLP) { w.Flags |= 1 << 9 },
		func(w *receiveCacheRLP) { w.Action = 256 + uint64(transport.ReceiveLedgerStart) }, func(w *receiveCacheRLP) { w.Ledger = 0 },
		func(w *receiveCacheRLP) { w.Scope = 1 }, func(w *receiveCacheRLP) { w.Request = 1 },
		func(w *receiveCacheRLP) { w.Origin = transport.ReceiveOrigin{WriterRun: "partial"} },
		func(w *receiveCacheRLP) { w.Source = transport.ReceiveAcceptSource{EngineRun: 1} },
		func(w *receiveCacheRLP) { w.Mono = ^uint64(0) }, func(w *receiveCacheRLP) { w.PendingAfter = 1 },
	} {
		bad := wire
		change(&bad)
		payload, err := rlp.Encode(&bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindReceiveCache, payload); err == nil {
			t.Fatal("invalid receive metadata accepted", bad)
		}
	}
}

func TestReceiveCacheMetadataRespectsQueueBudget(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := Open(Options{FS: fs, Dir: "/receive-budget", QueueRecords: 10, QueueBytes: 100}, ident())
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalReceiveTransitions{writer: writer, start: time.Now()}
	_, err = transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/receive-budget")
	if err != nil {
		t.Fatal(err)
	}
	dropped := uint64(0)
	for _, record := range records {
		if _, ok := record.Body.(*ReceiveCacheRec); ok {
			t.Fatal("receive metadata exceeded queue budget")
		}
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindReceiveCache) {
					dropped += kind.Count
				}
			}
		}
	}
	if dropped != 1 {
		t.Fatal("missing receive-cache gap", dropped)
	}
}

func TestReceiveCacheRecordFrozenContextUsesExactDecimals(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := Open(Options{FS: fs, Dir: "/context", Synchronous: true}, ident())
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalReceiveTransitions{writer: writer, start: time.Now()}
	ledger, err := transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	context := transport.ValidationContext{Sequence: "18446744073709551617", Round: "9007199254740993", PriorRound: "9007199254740992", State: "Preprepared"}
	scope := transport.NewValidationScopeWithContext(context)
	normal := deferredNormalMessage(t)
	in := transport.Inbound{Peer: normal.Peer, Code: uint64(normal.Code), Payload: normal.Payload}
	ticket, d := ledger.Prepare(scope, in, transport.ReceiveOrigin{})
	if d != transport.ReceiveReserved {
		t.Fatal(d)
	}
	scope.Close()
	ledger.Cancel(ticket)
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/context")
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, record := range records {
		r, ok := record.Body.(*ReceiveCacheRec)
		if !ok || r.Transition.Action != transport.ReceiveCheckPrepare {
			continue
		}
		if !r.Transition.ContextKnown || r.Transition.Context != context {
			t.Fatal("exact checking context lost", r.Transition.Context)
		}
		raw, err := encodeBody(record, record.JSeq)
		if err != nil {
			t.Fatal(err)
		}
		var wire receiveCacheRLP
		if err := rlp.DecodeStrict(raw, &wire); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*receiveCacheRLP){
			func(w *receiveCacheRLP) { w.Context.Sequence = "01" }, func(w *receiveCacheRLP) { w.Context.Round = "-1" },
			func(w *receiveCacheRLP) { w.Context.State = "unknown" }, func(w *receiveCacheRLP) { w.Context.ValidatorsPresent = 2 },
			func(w *receiveCacheRLP) { w.Flags &= ^uint64(256) }, func(w *receiveCacheRLP) { w.Flags |= 1 << 9 },
		} {
			invalid := wire
			change(&invalid)
			body, err := rlp.Encode(&invalid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeBody(KindReceiveCache, body); err == nil {
				t.Fatal("invalid context metadata accepted")
			}
		}
		matched++
	}
	if matched != 1 {
		t.Fatal("context preparation observation missing", matched)
	}
}
