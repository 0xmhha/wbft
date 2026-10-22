package journal

import (
	"crypto/sha256"
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

func writeCheckFixture(t *testing.T, record func(*journalWriteTransitions, *transport.WriteLedger)) []Record {
	t.Helper()
	fs := fsys.NewMem()
	id := ident()
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 64, ReceivePerPeer: 64, WritePending: 64, WritePerPeer: 64}}
	writer, err := Open(Options{FS: fs, Dir: "/check", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	observer := &journalWriteTransitions{writer: writer, start: time.Now()}
	ledger, err := transport.NewWriteLedger(transport.WriteLedgerOptions{Pending: 64, PerPeer: 64, KeyWithCode: true, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	record(observer, ledger)
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/check")
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestWriteCacheCheckNormalLRUEvictions(t *testing.T) {
	records := writeCheckFixture(t, func(_ *journalWriteTransitions, ledger *transport.WriteLedger) {
		key, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("normal-write-check-key")))
		if err != nil {
			t.Fatal(err)
		}
		target := transport.WritePeer{Addr: ecdsa.Address(key), Session: transport.NewWriteSession()}
		var first, last []byte
		for round := uint64(1); round <= uint64(transport.InmemoryMessages)+2; round++ {
			m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(round)}}
			signing, err := codec.SigningPayload(m, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			m.Signature, err = ecdsa.SignData(signing, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := codec.EncodeMessage(m)
			if err != nil {
				t.Fatal(err)
			}
			if round == 1 {
				first = raw
			}
			last = raw
			ticket, decision := ledger.Prepare(target, uint64(m.Code), raw)
			if decision != transport.WriteReserved {
				t.Fatal(decision)
			}
			if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: uint64(m.Code), PayloadSHA256: sha256.Sum256(raw), Result: transport.LocalWriteOK}) {
				t.Fatal("normal completion missing")
			}
			ledger.QueueResult(ticket, transport.Queued)
		}
		code := uint64(codec.CodeRoundChange)
		if _, d := ledger.Prepare(target, code, last); d != transport.WriteAlreadyRecent {
			t.Fatal("newest message evicted", d)
		}
		if _, d := ledger.Prepare(target, code, first); d != transport.WriteReserved {
			t.Fatal("oldest message retained", d)
		}
		// Normal accepted relays fill the bounded address LRU with the same signed input.
		for n := byte(1); n <= byte(transport.InmemoryPeers)+1; n++ {
			if !ledger.RecordAccepted(transport.WritePeer{Addr: types.Address{n}, Session: transport.NewWriteSession()}, code, last) {
				t.Fatal("normal accepted relay missing")
			}
		}
		if _, d := ledger.Prepare(target, code, last); d != transport.WriteReserved {
			t.Fatal("oldest peer retained", d)
		}
	})
	check, err := CheckWriteCacheTransitions(records, WriteCacheCheckLimits{Records: 10000, Ledgers: 16, Reordered: 128})
	if err != nil || check.Status != "consistent" || check.Ledgers != 1 || check.PhysicalStatus != "unavailable" {
		t.Fatal(check, err)
	}
	t.Logf("normal_signed_messages=%d reconstructed_transitions=%d physical_status=%s", transport.InmemoryMessages+2, check.Transitions, check.PhysicalStatus)
}

func TestWriteCacheCheckMissingAndContradictoryMetadata(t *testing.T) {
	records := writeCheckFixture(t, func(_ *journalWriteTransitions, ledger *transport.WriteLedger) {
		normal := deferredNormalMessage(t)
		target := transport.WritePeer{Addr: normal.Peer, Session: transport.NewWriteSession()}
		ticket, d := ledger.Prepare(target, uint64(normal.Code), normal.Payload)
		if d != transport.WriteReserved {
			t.Fatal(d)
		}
		if _, d := ledger.Prepare(target, uint64(normal.Code), normal.Payload); d != transport.WriteAlreadyPending {
			t.Fatal(d)
		}
		ledger.QueueResult(ticket, transport.Queued)
		if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: uint64(normal.Code), PayloadSHA256: sha256.Sum256(normal.Payload), Result: transport.LocalWriteOK}) {
			t.Fatal("normal write missing")
		}
	})
	limits := WriteCacheCheckLimits{Records: 1000, Ledgers: 4, Reordered: 4}
	check, err := CheckWriteCacheTransitions(records, limits)
	if err != nil || check.Status != "consistent" {
		t.Fatal(check, err)
	}
	var missing, contradictory []Record
	// These are detached retained-metadata copies, never transport input or live files.
	for _, record := range records {
		if r, ok := record.Body.(*WriteCacheRec); ok {
			if r.Transition.Sequence != 2 {
				missing = append(missing, record)
			}
			copyRec := *r
			if copyRec.Transition.Decision == transport.WriteAlreadyPending {
				copyRec.Transition.Decision = transport.WriteAlreadyRecent
			}
			record.Body = &copyRec
		} else {
			missing = append(missing, record)
		}
		contradictory = append(contradictory, record)
	}
	check, err = CheckWriteCacheTransitions(missing, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "missing_transition" {
		t.Fatal("missing sequence inferred", check, err)
	}
	check, err = CheckWriteCacheTransitions(contradictory, limits)
	if !errors.Is(err, ErrWriteCacheHistory) || check.Status != "inconsistent" {
		t.Fatal("false recent decision accepted", check, err)
	}
	check, err = CheckWriteCacheTransitions(records, WriteCacheCheckLimits{})
	if err != nil || check.Reason != "inspection_limits_required" {
		t.Fatal(check, err)
	}
	check, err = CheckWriteCacheTransitions(records, WriteCacheCheckLimits{Records: 1, Ledgers: 1, Reordered: 1})
	if err != nil || check.Reason != "record_limit" {
		t.Fatal(check, err)
	}
	gap := append([]Record(nil), records...)
	gap = append(gap, Record{Body: &GapRec{Dropped: 1, ByKind: []KindCount{{Kind: uint64(KindWriteCache), Count: 1}}}})
	check, err = CheckWriteCacheTransitions(gap, limits)
	if err != nil || check.Reason != "write_cache_gap" {
		t.Fatal("gap concealed", check, err)
	}
}

// Holding a record delays only observation delivery. Functional requests keep
// their original pointers and complete normally; no frame or result is changed.
type delayedWriteObservation struct {
	writer Writer
	held   *Record
}

func (w *delayedWriteObservation) Put(record Record) {
	if r, ok := record.Body.(*WriteCacheRec); ok && r.Transition.Sequence == 2 {
		copyRecord := record
		w.held = &copyRecord
		return
	}
	w.writer.Put(record)
	if w.held != nil {
		w.writer.Put(*w.held)
		w.held = nil
	}
}
func (w *delayedWriteObservation) Close() error { return w.writer.Close() }

func TestWriteCacheCheckDelayedObservationOrder(t *testing.T) {
	records := writeCheckFixture(t, func(observer *journalWriteTransitions, ledger *transport.WriteLedger) {
		observer.writer = &delayedWriteObservation{writer: observer.writer}
		normal := deferredNormalMessage(t)
		target := transport.WritePeer{Addr: normal.Peer, Session: transport.NewWriteSession()}
		ticket, d := ledger.Prepare(target, uint64(normal.Code), normal.Payload)
		if d != transport.WriteReserved {
			t.Fatal(d)
		}
		ledger.QueueResult(ticket, transport.Queued)
		if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: uint64(normal.Code), PayloadSHA256: sha256.Sum256(normal.Payload), Result: transport.LocalWriteOK}) {
			t.Fatal("normal completion missing")
		}
	})
	var seen []uint64
	for _, record := range records {
		if r, ok := record.Body.(*WriteCacheRec); ok {
			seen = append(seen, r.Transition.Sequence)
		}
	}
	if len(seen) < 3 || seen[0] != 1 || seen[1] != 3 || seen[2] != 2 {
		t.Fatal("observation delay was not exercised", seen)
	}
	check, err := CheckWriteCacheTransitions(records, WriteCacheCheckLimits{Records: 1000, Ledgers: 4, Reordered: 1})
	if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" {
		t.Fatal(check, err)
	}
}
