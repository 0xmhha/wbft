package main

import (
	"bytes"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestExportOutcomeSourceIdentity(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "source-identity"})
	if err != nil {
		t.Fatal(err)
	}
	key := codec.DedupKey([]byte{1, 2, 3})
	writer.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: nodeA, DedupKey: key,
		Outcome: event.Accept, Check: "PROCESS", Row: 3, Via: "self", Step: 7}})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 0, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	records := readFrames(t, fs, "/out/frames-source-identity.jsonl")
	if len(records) != 1 {
		t.Fatalf("outcome count: %d", len(records))
	}
	r := records[0]
	if r["code"] != "0x13" || r["peer"] != nodeA.Hex() || r["dedup_key"] != key.Hex() || r["step"] != float64(7) {
		t.Fatalf("outcome source identity lost: %v", r)
	}
	if r["of"] != nil || r["internal_input"] != nil {
		t.Fatalf("legacy outcome invented input evidence: %v", r)
	}
}

func ownSignedPayload(t *testing.T) (types.Address, []byte) {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = 1 // public synthetic fixture scalar
	key, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		t.Fatal(err)
	}
	msg := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(10)}}
	signing, err := codec.SigningPayload(msg, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature, err = ecdsa.SignData(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return ecdsa.Address(key), payload
}

func TestExportOwnRelayInputEvidence(t *testing.T) {
	for _, name := range []string{"valid", "peer-input", "wrong-peer", "wrong-key", "wrong-code", "wrong-step", "wrong-engine", "legacy", "at-offer", "not-accepted", "unprocessed", "invalid-signature", "other-signer", "gap-before", "gap-after", "missing-step", "duplicate-step", "duplicate-outcome", "repeated-bytes"} {
		t.Run(name, func(t *testing.T) {
			self, payload := ownSignedPayload(t)
			if name == "other-signer" {
				self = peerB
			}
			fs := fsys.NewMem()
			writer, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: self, Run: "own"})
			if err != nil {
				t.Fatal(err)
			}
			put := func(body any) { writer.Put(journal.Record{Body: body}) }
			put(&journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"})
			put(&journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart})
			// The transport can finish its write before the outcome and step.
			put(&journal.MsgRec{Dir: journal.Out, PeerIdx: 1, Code: 0x13, Payload: payload, DedupKey: codec.DedupKey(payload), Cause: event.CauseRelay, Write: "ok"})
			outcome := &journal.OutcomeRec{Code: 0x13, Peer: self, DedupKey: codec.DedupKey(payload), Outcome: event.Accept, Check: "PROCESS", Via: "self", Step: 7, EngineRun: 1}
			msg := consensus.Message{Code: codec.CodePrepare, Peer: self, Payload: payload}
			step := &journal.StepRec{EngineRun: 1, Step: 7, Via: "internal", InputKind: inputlog.KindMessage}
			switch name {
			case "peer-input":
				step.Via = "peer"
			case "wrong-peer":
				msg.Peer = peerB
			case "wrong-key":
				outcome.DedupKey = types.Hash{9}
			case "wrong-code":
				outcome.Code = 0x14
			case "wrong-step":
				outcome.Step++
			case "wrong-engine":
				outcome.EngineRun++
			case "legacy":
				outcome.EngineRun = 0
			case "at-offer":
				outcome.AtOffer = true
			case "not-accepted":
				outcome.Outcome = event.Ignore
			case "unprocessed":
				outcome.Check = "prefilter"
			case "invalid-signature":
				msg.Payload = bytes.Clone(payload)
				msg.Payload[len(msg.Payload)-1] = 9
				outcome.DedupKey = codec.DedupKey(msg.Payload)
			}
			step.Input, err = inputlog.Encode(msg)
			if err != nil {
				t.Fatal(err)
			}
			put(outcome)
			if name == "duplicate-outcome" {
				copy := *outcome
				put(&copy)
			}
			if name == "gap-before" {
				put(&journal.GapRec{Dropped: 1})
			}
			if name != "missing-step" {
				put(step)
			}
			if name == "duplicate-step" {
				copy := *step
				put(&copy)
			}
			if name == "repeated-bytes" {
				o, s := *outcome, *step
				o.EngineRun, s.EngineRun = 2, 2
				put(&o)
				put(&s)
			}
			if name == "gap-after" {
				put(&journal.GapRec{Dropped: 1})
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			var result exportResult
			runJSON(t, fs, 0, &result, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
			records := readFrames(t, fs, "/out/frames-own.jsonl")
			var relay, witness, accepted map[string]any
			for _, r := range records {
				switch r["type"] {
				case "frame":
					relay = r
				case "own_input":
					witness = r
				case "outcome":
					if r["input_of"] != nil {
						accepted = r
					}
				}
			}
			if relay == nil || relay["relay_of"] != nil {
				t.Fatal("invented received frame", relay)
			}
			if name != "valid" {
				if relay["own_message_of"] != nil || result.Unlinked == 0 {
					t.Fatal("unproved own provenance", name, records, result)
				}
				return
			}
			if witness == nil || accepted == nil || relay["own_message_of"] != accepted["seq"] || accepted["input_of"] != witness["seq"] || result.Unlinked != 0 {
				t.Fatal("missing own provenance", records, result)
			}
			if witness["engine_run"] != float64(1) || witness["step"] != float64(7) || witness["peer"] != strings.ToLower(self.Hex()) || witness["via"] != "internal" || witness["payload_sha256"] != sum(payload) || witness["dedup_key"] != codec.DedupKey(payload).Hex() || witness["code"] != "0x13" {
				t.Fatal("wrong input identity", witness)
			}
			var source wal.Position
			err = scan(fs, "/j", func(rec journal.Record, pos wal.Position) {
				if float64(rec.JSeq) == witness["seq"] {
					source = pos
				}
			})
			if err != nil || witness["journal_segment"] != float64(source.Segment) || witness["journal_offset"] != float64(source.Offset) {
				t.Fatal("wrong source position", err, source, witness)
			}
			retained, err := fs.ReadFile("/out/payloads/" + sum(payload)[:2] + "/" + sum(payload))
			if err != nil || !bytes.Equal(retained, payload) {
				t.Fatal("payload changed", err)
			}
		})
	}
}

type changingJournalFS struct {
	fsys.FS
	reads  int
	mutate func()
}

func (fs *changingJournalFS) ReadFile(name string) ([]byte, error) {
	if strings.HasSuffix(name, ".wal") {
		fs.reads++
		if fs.reads == 2 {
			fs.mutate()
		}
	}
	return fs.FS.ReadFile(name)
}

func TestOwnInputExportRejectsChangingJournal(t *testing.T) {
	self, payload := ownSignedPayload(t)
	mem := fsys.NewMem()
	j, err := journal.Open(journal.Options{FS: mem, Dir: "/j", Synchronous: true}, journal.Identity{Self: self, Run: "changing"})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: self, DedupKey: codec.DedupKey(payload), Via: "self", Outcome: event.Accept, Check: "PROCESS", Step: 7, EngineRun: 1}})
	body, err := inputlog.Encode(consensus.Message{Code: codec.CodePrepare, Peer: self, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	j.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 7, Via: "internal", InputKind: inputlog.KindMessage, Input: body}})
	if err := j.Sync(); err != nil {
		t.Fatal(err)
	}
	fs := &changingJournalFS{FS: mem, mutate: func() {
		j.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
		if err := j.Sync(); err != nil {
			t.Fatal(err)
		}
	}}
	_, err = exportR01(fs, "/j", "/out", "", "")
	if err == nil || !strings.Contains(err.Error(), "journal changed while own input evidence was indexed") {
		t.Fatal("changing source accepted", fs.reads, err)
	}
}
