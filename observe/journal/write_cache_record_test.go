package journal

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
)

type journalWriteTransitions struct {
	writer   Writer
	observed []transport.WriteTransition
	start    time.Time
}

func (o *journalWriteTransitions) ObserveWriteTransition(event transport.WriteTransition) {
	o.observed = append(o.observed, event)
	now := time.Now()
	o.writer.Put(Record{Body: &WriteCacheRec{Transition: event, Mono: now.Sub(o.start), WallNs: now.UnixNano()}})
}

func TestWriteCacheJournalActualLedgerLifecycle(t *testing.T) {
	fs := fsys.NewMem()
	id := ident()
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}}
	writer, err := Open(Options{FS: fs, Dir: "/write-cache", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalWriteTransitions{writer: writer, start: time.Now()}
	ledger, err := transport.NewWriteLedger(transport.WriteLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	normal := deferredNormalMessage(t)
	if recovered, err := consensus.Recover(normal.Code, normal.Payload, nil); err != nil || recovered.Source != normal.Peer {
		t.Fatal("normal signed fixture did not recover", err)
	}
	target := transport.WritePeer{Addr: normal.Peer, Session: transport.NewWriteSession()}
	code := uint64(normal.Code)
	ticket, decision := ledger.Prepare(target, code, normal.Payload)
	if decision != transport.WriteReserved {
		t.Fatal(decision)
	}
	if _, d := ledger.Prepare(target, code, normal.Payload); d != transport.WriteAlreadyPending {
		t.Fatal(d)
	}
	ledger.QueueResult(ticket, transport.Queued)
	target.Session.Close()
	if ledger.Pending() != 0 {
		t.Fatal("closed stream retained pending")
	}
	ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(normal.Payload), Result: transport.LocalWriteCancelled})
	target.Session = transport.NewWriteSession()
	ticket, decision = ledger.Prepare(target, code, normal.Payload)
	if decision != transport.WriteReserved {
		t.Fatal(decision)
	}
	if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(normal.Payload), Result: transport.LocalWriteOK}) {
		t.Fatal("normal completion was lost")
	}
	ledger.QueueResult(ticket, transport.Queued)
	if _, d := ledger.Prepare(target, code, normal.Payload); d != transport.WriteAlreadyRecent {
		t.Fatal(d)
	}
	if !ledger.RecordAccepted(target, code, normal.Payload) {
		t.Fatal("accepted input not registered")
	}
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/write-cache")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, record := range records {
		r, ok := record.Body.(*WriteCacheRec)
		if !ok {
			continue
		}
		if record.Kind != KindWriteCache || r.Transition.Sequence != uint64(count+1) {
			t.Fatal("lost actual ledger ordering")
		}
		raw, err := encodeBody(record, record.JSeq)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindWriteCache, raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := encodeBody(decoded, record.JSeq)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("actual cache observation bytes changed", err)
		}
		if writeFlags(r.Transition) != writeFlags(observer.observed[count]) {
			t.Fatal("actual transition flags changed")
		}
		count++
	}
	if count != len(observer.observed) || count < 10 {
		t.Fatal("actual ledger observations missing", count, len(observer.observed))
	}
	if _, err := id.Core.Configuration(); err == nil {
		t.Fatal("record decoding silently enabled runtime replay")
	}
}

func TestWriteCacheRecordStrictShapeAndIntegerLimits(t *testing.T) {
	declaration := &WriteCacheRec{Transition: transport.WriteTransition{Ledger: ^uint64(0), Sequence: 1, Action: transport.WriteStart, PendingLimit: ^uint64(0), PerPeerLimit: (1 << 53) + 1, KeyWithCode: true}}
	raw, err := encodeBody(Record{Body: declaration}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindWriteCache, raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.JSeq != ^uint64(0) || decoded.Body.(*WriteCacheRec).Transition.PerPeerLimit != (1<<53)+1 {
		t.Fatal("large integer lost")
	}
	var wire writeCacheRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// Invalid metadata shapes are codec inputs, never injected network frames.
	for _, change := range []func(*writeCacheRLP){
		func(w *writeCacheRLP) { w.Format++ }, func(w *writeCacheRLP) { w.Action = 256 + uint64(transport.WriteStart) },
		func(w *writeCacheRLP) { w.Flags |= 1 << 8 }, func(w *writeCacheRLP) { w.Ledger = 0 },
		func(w *writeCacheRLP) { w.Sequence = 0 }, func(w *writeCacheRLP) { w.PerPeerLimit = 0 },
		func(w *writeCacheRLP) { w.PendingBefore = 1 }, func(w *writeCacheRLP) { w.Request = 2 },
		func(w *writeCacheRLP) { w.Mono = ^uint64(0) }, func(w *writeCacheRLP) { w.Pruned = []uint64{1} },
	} {
		invalid := wire
		change(&invalid)
		payload, err := rlp.Encode(&invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindWriteCache, payload); err == nil {
			t.Fatal("invalid cache metadata accepted", invalid)
		}
	}
}

func TestWriteCacheMetadataRespectsQueueBudget(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := Open(Options{FS: fs, Dir: "/write-cache-budget", QueueRecords: 10, QueueBytes: 100}, ident())
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalWriteTransitions{writer: writer, start: time.Now()}
	_, err = transport.NewWriteLedger(transport.WriteLedgerOptions{Pending: 16, PerPeer: 4, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/write-cache-budget")
	if err != nil {
		t.Fatal(err)
	}
	dropped := uint64(0)
	for _, record := range records {
		if _, ok := record.Body.(*WriteCacheRec); ok {
			t.Fatal("write-cache metadata exceeded byte budget")
		}
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindWriteCache) {
					dropped += kind.Count
				}
			}
		}
	}
	if dropped != 1 {
		t.Fatal("missing write-cache gap", dropped)
	}
}
