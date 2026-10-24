package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type checkCommandObserver struct {
	writer journal.Writer
	start  time.Time
}

func (o checkCommandObserver) ObserveWriteTransition(event transport.WriteTransition) {
	now := time.Now()
	o.writer.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: event, Mono: now.Sub(o.start), WallNs: now.UnixNano()}})
}

func TestCheckWriteCacheCommandNormalJournal(t *testing.T) {
	fs := fsys.NewMem()
	limits := transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}
	writer, err := journal.Open(journal.Options{FS: fs, Dir: "/completed", Synchronous: true}, journal.Identity{Run: "normal-command", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}}})
	if err != nil {
		t.Fatal(err)
	}
	opt := limits.WriteOptions()
	opt.Trace = checkCommandObserver{writer: writer, start: time.Now()}
	ledger, err := transport.NewWriteLedger(opt)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("normal-cache-command")))
	if err != nil {
		t.Fatal(err)
	}
	msg := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(1)}}
	signing, err := codec.SigningPayload(msg, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature, err = ecdsa.SignData(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	target := transport.WritePeer{Addr: ecdsa.Address(key), Session: transport.NewWriteSession()}
	ticket, d := ledger.Prepare(target, uint64(msg.Code), raw)
	if d != transport.WriteReserved {
		t.Fatal(d)
	}
	ledger.QueueResult(ticket, transport.Queued)
	if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: uint64(msg.Code), PayloadSHA256: sha256.Sum256(raw), Result: transport.LocalWriteOK}) {
		t.Fatal("normal completion missing")
	}
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var check journal.WriteCacheCheck
	args := []string{"check-write-cache", "--dir", "/completed", "--max-records", "100", "--max-ledgers", "4", "--max-reordered", "4"}
	runJSON(t, fs, 0, &check, args...)
	if check.Status != "consistent" || check.PhysicalStatus != "unavailable" || check.Ledgers != 1 {
		t.Fatal(check)
	}
	runJSON(t, fs, 2, nil, "check-write-cache", "--dir", "/completed")
	args[4] = "1"
	runJSON(t, fs, 69, &check, args...)
	if check.Reason != "record_limit" {
		t.Fatal(check)
	}
	// An original journal without this capability remains explicitly unavailable.
	writeJournal(t, fs)
	runJSON(t, fs, 69, &check, "check-write-cache", "--dir", "/j", "--max-records", "1000", "--max-ledgers", "4", "--max-reordered", "4")
	if check.Reason != "no_write_cache_trace" {
		t.Fatal(check)
	}
}

func TestWriteCacheR01ProjectionRemainsUnavailable(t *testing.T) {
	for _, legacy := range []uint64{0, journal.CacheTraceVersion} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			fs := fsys.NewMem()
			writer, err := journal.Open(journal.Options{FS: fs, Dir: "/new-profile", Synchronous: true}, journal.Identity{Run: "new-profile", Core: journal.CoreOptions{CacheTrace: legacy, CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := exportR01(fs, "/new-profile", "/out", "", ""); err == nil || !strings.Contains(err.Error(), "accepted/completed cache profile") {
				t.Fatal("new profile projected as legacy cache evidence", err)
			}
			if entries, err := fs.ReadDir("/out"); err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry, ".jsonl") {
						t.Fatal("unsupported projection emitted rows")
					}
				}
			}
		})
	}
}

type unsupportedReceiveRecordObserver struct{ writer journal.Writer }

func (o unsupportedReceiveRecordObserver) ObserveReceiveTransition(event transport.ReceiveTransition) {
	o.writer.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: event}})
}
func TestReceiveCacheRecordR01ProjectionUnavailableWithoutProfile(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := journal.Open(journal.Options{FS: fs, Dir: "/receive-kind", Synchronous: true}, journal.Identity{Run: "receive-kind"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.NewReceiveLedger(transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: unsupportedReceiveRecordObserver{writer}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := exportR01(fs, "/receive-kind", "/out-receive", "", ""); err == nil || !strings.Contains(err.Error(), "accepted-receive cache observations") {
		t.Fatal("new receive kind projected as legacy cache", err)
	}
}

func TestSessionSourceR01ProjectionUnavailableWithoutProfile(t *testing.T) {
	for _, legacy := range []uint64{0, journal.CacheTraceVersion} {
		for _, domain := range []string{"lifetime", "frame", "write_attempt", "core_step", "app_queue", "finalize", "inbox", "internal", "selection"} {
			t.Run(fmt.Sprintf("%s/%d", domain, legacy), func(t *testing.T) {
				fs := fsys.NewMem()
				writer, err := journal.Open(journal.Options{FS: fs, Dir: "/session-source", Synchronous: true}, journal.Identity{Run: "current-writer", Core: journal.CoreOptions{CacheTrace: legacy}})
				if err != nil {
					t.Fatal(err)
				}
				ref := &journal.SessionRef{Run: "original-writer", Ordinal: 7}
				switch domain {
				case "lifetime":
					writer.Put(journal.Record{Body: &journal.SessionRec{Session: ref, Event: journal.SessionObserved, Active: true}})
				case "selection":
					writer.Put(journal.Record{Body: &journal.SelectionRec{Version: journal.SelectionSourceVersion, Sequence: 1, Selection: 1, EngineRun: 1, Step: 1, Action: "select", Lane: "none", Internal: journal.InputProbe{State: "empty"}, App: journal.InputProbe{State: "empty"}, Timer: journal.InputProbe{State: "empty"}, Inbox: journal.InputProbe{State: "empty"}, NextHeight: "disabled"}})
				case "internal":
					writer.Put(journal.Record{Body: &journal.InternalRec{Version: journal.InternalSourceVersion, Sequence: 1, EngineRun: 1, Action: "reset"}})
				case "inbox":
					writer.Put(journal.Record{Body: &journal.InboxRec{Version: journal.InboxSourceVersion, Sequence: 1, EngineRun: 1, Step: 1, Action: "clear"}})
				case "finalize":
					writer.Put(journal.Record{Body: &journal.FinalizeRec{Version: journal.FinalizeSourceVersion, Sequence: 1, Task: 1, EngineRun: 1, Step: 1, Output: 1, Action: "return"}})
				case "app_queue":
					input, e := inputlog.Encode(consensus.PeerConnected{Addr: types.Address{3}})
					if e != nil {
						t.Fatal(e)
					}
					writer.Put(journal.Record{Body: &journal.AppQueueRec{Version: journal.AppQueueSourceVersion, Sequence: 1, Request: 1, Action: "append", InputKind: inputlog.KindPeerConnected, Input: input, After: 1}})
				case "core_step":
					input, e := inputlog.Encode(consensus.Start{})
					if e != nil {
						t.Fatal(e)
					}
					outputs, e := inputlog.EncodeOutputs(nil)
					if e != nil {
						t.Fatal(e)
					}
					digest, e := inputlog.OutDigest(nil)
					if e != nil {
						t.Fatal(e)
					}
					writer.Put(journal.Record{Body: &journal.CoreStepRec{EngineRun: 1, Step: 1, Via: "engine", InputKind: inputlog.KindStart, Input: input, Outputs: outputs, OutDigest: digest}})
				case "write_attempt":
					writer.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, WriteAttempt: &journal.WriteAttemptSource{Sequence: 1, WriterRun: "original-writer", Ledger: 1, Request: 2}}})
				default:
					writer.Put(journal.Record{Body: &journal.MsgRec{Session: ref, Dir: journal.In, Code: uint64(codec.CodeRoundChange)}})
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				expected := "session"
				if domain == "core_step" {
					expected = "core step sources"
				}
				if domain == "selection" {
					expected = "input selection sources"
				}
				if domain == "internal" {
					expected = "internal sources"
				}
				if domain == "inbox" {
					expected = "inbox sources"
				}
				if domain == "finalize" {
					expected = "finalization sources"
				}
				if domain == "app_queue" {
					expected = "application queue sources"
				}
				if _, err := exportR01(fs, "/session-source", "/session-out", "", ""); err == nil || !strings.Contains(err.Error(), expected) {
					t.Fatal("session sources projected with legacy semantics", err)
				}
				if entries, err := fs.ReadDir("/session-out"); err == nil {
					for _, name := range entries {
						if strings.HasSuffix(name, ".jsonl") {
							t.Fatal("unsupported source emitted a partial result")
						}
					}
				}
			})
		}
	}
}
