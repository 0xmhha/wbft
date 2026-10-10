package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

var (
	nodeA = types.Address{0xaa}
	peerB = types.Address{0xbb}
)

// frameJournal writes one run with a peer stream, received and sent
// frames, outcomes before and after their frames, and a step that moves the
// head to 5 before the last frame.
func frameJournal(t *testing.T, fs fsys.FS) (p1, p2 []byte) {
	t.Helper()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", SegmentBytes: 400, Synchronous: true},
		journal.Identity{Self: nodeA, Run: "run/1", Mode: "standalone"})
	if err != nil {
		t.Fatal(err)
	}
	p1, p2 = []byte{0xc1, 0x01}, []byte{0xc1, 0x02}
	msg := func(dir string, p []byte, offer, write string) {
		jw.Put(journal.Record{Body: &journal.MsgRec{Dir: dir, PeerIdx: 1, Mono: 7 * time.Second, WallNs: 1_700_000_000_123_456_789,
			Code: 0x12, WireCode: 0x22, Payload: p, DedupKey: codec.DedupKey(p), Offer: offer, Write: write}})
	}
	outcome := func(p []byte, class event.OutcomeClass) {
		jw.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x12, Peer: peerB, DedupKey: codec.DedupKey(p), Outcome: class,
			Check: "PROCESS", Row: 3, Via: "direct"}})
	}
	jw.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: "start", HeadNumber: types.HeightFromUint64(0)}})
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, NodeID: []byte{1, 2}, Remote: "10.0.0.2:1", Event: "attached"}})
	msg(journal.In, p1, "queued", "")
	outcome(p1, event.Accept) // after its frame
	outcome(p2, event.Ignore) // before its frame
	msg(journal.In, p2, "queued", "")
	msg(journal.In, []byte{1}, "frame_ignore", "")
	msg(journal.Out, p1, "", "ok")
	msg(journal.Out, p2, "", "not_attached")
	outcome([]byte{9}, event.Accept) // no frame at all
	jw.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: nodeA, DedupKey: codec.DedupKey([]byte{8}), Outcome: event.Accept,
		Check: "PROCESS", Row: 3, Via: "self"}})
	jw.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 2, InputKind: "timer", HeadNumber: types.HeightFromUint64(5)}})
	msg(journal.In, p1, "frame_disconnect", "")
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "closed", Reason: "frame rejected"}})
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	return p1, p2
}

func readFrames(t *testing.T, fs *fsys.Mem, name string) []map[string]any {
	t.Helper()
	b, err := fs.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	return out
}

func sum(p []byte) string { s := sha256.Sum256(p); return hex.EncodeToString(s[:]) }

// TestExportR01 checks the records of the frame dump: the common fields,
// frames in and out with their outcomes and write errors, outcomes linked
// to their frames in either journal order, conn records without the
// repeats of segment headers, and the content-addressed payloads.
func TestExportR01(t *testing.T) {
	fs := fsys.NewMem()
	p1, p2 := frameJournal(t, fs)
	if segs, err := wal.Segments(fs, "/j"); err != nil || len(segs) < 2 {
		t.Fatalf("want a journal of several segments: %d %v", len(segs), err)
	}
	var res exportResult
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	if len(res.Runs) != 1 || res.Runs[0].File != "frames-run_1.jsonl" || res.Payloads != 3 || res.Unlinked != 1 {
		t.Fatalf("result %+v %+v", res, res.Runs)
	}
	recs := readFrames(t, fs, "/out/frames-run_1.jsonl")
	var got []string
	seqOf := map[string]float64{}
	for _, r := range recs {
		if r["v"] != float64(1) || r["node"] != hexAddr(nodeA) || r["run"] != "run/1" || r["t_wall"] != "2023-11-14T22:13:20.123456789Z" && r["type"] != "conn" {
			t.Fatalf("common fields %v", r)
		}
		line := r["type"].(string)
		switch line {
		case "frame":
			line += " " + r["dir"].(string) + " " + r["payload_sha256"].(string)[:4]
			if r["dir"] == "in" {
				line += " " + r["outcome"].(string)
				seqOf[r["payload_sha256"].(string)[:4]] = r["seq"].(float64)
			} else if e, ok := r["write_error"]; ok {
				line += " " + e.(string)
			}
			if r["peer"] != hexAddr(peerB) || r["peer_id"] != "0102" || r["code"] != "0x12" || r["wire_code"] != float64(0x22) {
				t.Fatalf("frame %v", r)
			}
		case "outcome":
			line += " " + r["outcome"].(string)
			if of, ok := r["of"].(float64); ok {
				for k, s := range seqOf {
					if s == of {
						line += " of " + k
					}
				}
			} else {
				line += " of null"
			}
			if r["check"] != "PROCESS" || (r["via"] != "direct" && r["via"] != "self") || r["row"] != float64(3) || r["error_class"] != nil {
				t.Fatalf("outcome %v", r)
			}
		case "conn":
			line += " " + r["event"].(string)
		}
		got = append(got, line)
	}
	s1, s2, s3 := sum(p1)[:4], sum(p2)[:4], sum([]byte{1})[:4]
	want := []string{
		"conn istanbul_attached",
		"frame in " + s1 + " PENDING",
		"outcome ACCEPT of " + s1,
		"frame in " + s2 + " PENDING",
		"outcome IGNORE of " + s2,
		"frame in " + s3 + " DROP_SILENT",
		"frame out " + s1,
		"frame out " + s2 + " not_attached",
		"outcome ACCEPT of null", // the node's own message, written at once
		"frame in " + s1 + " DISCONNECT",
		"conn closed",
		"outcome ACCEPT of null",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("records\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, p := range [][]byte{p1, p2} {
		s := sum(p)
		if b, err := fs.ReadFile("/out/payloads/" + s[:2] + "/" + s); err != nil || !bytes.Equal(b, p) {
			t.Fatalf("payload %s: %x %v", s, b, err)
		}
	}

	// The frame file of a run is not overwritten.
	runJSON(t, fs, 2, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
}

// TestExportRange keeps the records whose height (head + 1) is in range.
func TestExportRange(t *testing.T) {
	fs := fsys.NewMem()
	frameJournal(t, fs)
	var res exportResult
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/out", "--format", "r01", "--from", "6", "--to", "6")
	recs := readFrames(t, fs, "/out/frames-run_1.jsonl")
	if len(recs) != 2 || recs[0]["outcome"] != "DISCONNECT" || recs[1]["event"] != "closed" {
		t.Fatalf("records %v", recs)
	}
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/out2", "--format", "r01", "--to", "1")
	if recs := readFrames(t, fs, "/out2/frames-run_1.jsonl"); len(recs) != 10 {
		t.Fatalf("%d records up to height 1", len(recs))
	}
}

// TestExportUsage refuses an unknown format, a missing --out and a bad
// height.
func TestExportUsage(t *testing.T) {
	fs := fsys.NewMem()
	frameJournal(t, fs)
	runJSON(t, fs, 2, nil, "export", "--dir", "/j", "--out", "/out", "--format", "zip")
	runJSON(t, fs, 2, nil, "export", "--dir", "/j", "--format", "r01")
	runJSON(t, fs, 2, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01", "--from", "x")
}

// TestExportSizes writes the kept size of a frame whose payload was not
// kept, without a payload hash, and an empty payload as a payload of its
// own (inspector rules on empty payloads need its hash).
func TestExportSizes(t *testing.T) {
	fs := fsys.NewMem()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "r"})
	if err != nil {
		t.Fatal(err)
	}
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x12, WireCode: 0x12, Size: 20 << 20,
		Offer: "frame_disconnect"}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: []byte{},
		DedupKey: codec.DedupKey(nil), Offer: "frame_disconnect"}})
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 0, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	recs := readFrames(t, fs, "/out/frames-r.jsonl")
	if len(recs) != 3 {
		t.Fatalf("records %v", recs)
	}
	if big := recs[1]; big["size"] != float64(20<<20) || big["payload_sha256"] != nil {
		t.Fatalf("large frame %v", big)
	}
	empty := recs[2]
	if empty["size"] != float64(0) || empty["payload_sha256"] != sum(nil) {
		t.Fatalf("empty frame %v", empty)
	}
	if b, err := fs.ReadFile("/out/payloads/" + sum(nil)[:2] + "/" + sum(nil)); err != nil || len(b) != 0 {
		t.Fatalf("empty payload file %x %v", b, err)
	}
}

// TestExportRelayOf links a relay to the received frame with the same
// bytes, from whichever peer, and leaves other causes without relay_of;
// suppressed sends keep their cause and reason.
func TestExportRelayOf(t *testing.T) {
	fs := fsys.NewMem()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "r"})
	if err != nil {
		t.Fatal(err)
	}
	p := []byte{0xc1, 0x0a}
	k := codec.DedupKey(p)
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: types.Address{0xcc}, Event: "attached"}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k, Offer: "queued",
		Engine: "running", Dedup: &journal.DedupHits{PeerRecent: true}}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 2, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k, Write: "ok",
		Cause: event.CauseRelay}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 2, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k, Write: "ok",
		Cause: event.CauseBroadcast}})
	jw.Put(journal.Record{Body: &journal.SuppressedRec{PeerIdx: 1, DedupKey: k, Cause: event.CauseRelay, Reason: "peer_recent_cache"}})
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 0, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	recs := readFrames(t, fs, "/out/frames-r.jsonl")
	if len(recs) != 6 {
		t.Fatalf("records %v", recs)
	}
	in, relay, own, sup := recs[2], recs[3], recs[4], recs[5]
	if in["engine"] != "running" || relay["engine"] != nil {
		t.Fatalf("engine state: in %v, out %v", in["engine"], relay["engine"])
	}
	if fmt.Sprint(in["dedup"]) != "map[known_hit:false peer_recent_hit:true]" || relay["dedup"] != nil {
		t.Fatalf("dedup: in %v, out %v", in["dedup"], relay["dedup"])
	}
	if relay["cause"] != "relay" || relay["relay_of"] != in["seq"] {
		t.Fatalf("relay %v of %v", relay, in)
	}
	if own["cause"] != "broadcast" || own["relay_of"] != nil {
		t.Fatalf("own send %v", own)
	}
	if sup["type"] != "send_suppressed" || sup["cause"] != "relay" || sup["reason"] != "peer_recent_cache" || sup["peer"] != hexAddr(peerB) {
		t.Fatalf("suppressed %v", sup)
	}
}

// TestExportRelayBeforeReceipt links a relay journaled before the frame it
// relays to that frame and writes it after the frame; a relay of a message
// never received has no relay_of and is counted as unlinked.
func TestExportRelayBeforeReceipt(t *testing.T) {
	fs := fsys.NewMem()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "r"})
	if err != nil {
		t.Fatal(err)
	}
	p, q := []byte{0xc1, 0x0a}, []byte{0xc1, 0x0b}
	k := codec.DedupKey(p)
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: types.Address{0xcc}, Event: "attached"}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 2, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k, Write: "ok",
		Cause: event.CauseRelay}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 2, Code: 0x13, WireCode: 0x13, Payload: q, DedupKey: codec.DedupKey(q), Write: "ok",
		Cause: event.CauseRelay}})
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k, Offer: "queued",
		Engine: "running", Dedup: &journal.DedupHits{}}})
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	var res exportResult
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	recs := readFrames(t, fs, "/out/frames-r.jsonl")
	if len(recs) != 5 || res.Unlinked != 1 {
		t.Fatalf("records %v, unlinked %d", recs, res.Unlinked)
	}
	in, relay, lost := recs[2], recs[3], recs[4]
	if in["dir"] != "in" || relay["cause"] != "relay" || relay["relay_of"] != in["seq"] || relay["seq"].(float64) >= in["seq"].(float64) {
		t.Fatalf("relay %v of %v", relay, in)
	}
	if lost["cause"] != "relay" || lost["relay_of"] != nil || lost["dedup_key"] == relay["dedup_key"] {
		t.Fatalf("relay of a message not received: %v", lost)
	}
}

// TestExportCloses writes who closed each stream and links a close for one
// received frame to the frame that ended DISCONNECT: after the frame for the
// frame stage, and, for the stopped engine, after the frame its outcome
// (journaled first, like the close) belongs to. A close the journal has no
// By for reads unknown.
func TestExportCloses(t *testing.T) {
	fs := fsys.NewMem()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "r"})
	if err != nil {
		t.Fatal(err)
	}
	p := []byte{0xc1, 0x0c}
	k := codec.DedupKey(p)
	attach := func() { jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}}) }
	closed := func(by, cause string) {
		jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "closed", Reason: "x", By: by, Cause: cause}})
	}
	attach()
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x12, WireCode: 0x12, Payload: nil, Offer: "frame_disconnect"}}) // seq 3
	closed("self", "frame")
	attach()
	jw.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: peerB, DedupKey: k, Outcome: "DISCONNECT", Check: "prefilter",
		Row: -1, Reason: "engine_stopped", Via: "direct", AtOffer: true}})
	closed("self", "engine_stopped")
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k,
		Offer: "queued", Engine: "stopped"}}) // seq 8
	attach()
	closed("peer", "")
	attach()
	closed("", "")
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 0, nil, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	var got []string
	for _, r := range readFrames(t, fs, "/out/frames-r.jsonl") {
		switch {
		case r["type"] == "conn" && r["event"] == "closed":
			got = append(got, fmt.Sprintf("closed by %v cause %v of %v", r["by"], r["cause"], r["of"]))
		case r["type"] == "frame":
			got = append(got, fmt.Sprintf("frame %v %v", r["seq"], r["outcome"]))
		}
	}
	want := []string{
		"frame 3 DISCONNECT", "closed by self cause frame of 3",
		"frame 8 PENDING", "closed by self cause engine_stopped of 8",
		"closed by peer cause <nil> of <nil>", "closed by unknown cause <nil> of <nil>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("records\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestExportBundle writes a bundle file with its manifest and does not
// overwrite an existing file.
func TestExportBundle(t *testing.T) {
	fs := fsys.NewMem()
	writeJournal(t, fs)
	var res bundleResult
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/b.tar", "--from", "15", "--to", "16")
	if res.Format != "bundle" || res.Manifest == nil || len(res.Manifest.Files) == 0 || res.Manifest.Heights.Warmup != 2 {
		t.Fatalf("result %+v", res)
	}
	b, err := fs.ReadFile("/b.tar")
	if err != nil {
		t.Fatal(err)
	}
	m, err := journal.ReadBundle(bytes.NewReader(b), fs, "/x")
	if err != nil || len(m.Files) != len(res.Manifest.Files) {
		t.Fatalf("read back %+v: %v", m, err)
	}
	runJSON(t, fs, 2, nil, "export", "--dir", "/j", "--out", "/b.tar")
}

// TestExportOfferOutcomes links an outcome decided while a frame was
// offered to that frame, journaled after it, and the core's outcome of an
// earlier copy from the same peer to that copy, although the second copy
// came in between; a frame the receiver did not take is not a target.
func TestExportOfferOutcomes(t *testing.T) {
	fs := fsys.NewMem()
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "r"})
	if err != nil {
		t.Fatal(err)
	}
	p := []byte{0xc1, 0x0b}
	k := codec.DedupKey(p)
	in := func(offer string, hits *journal.DedupHits) {
		jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: p, DedupKey: k,
			Offer: offer, Engine: "running", Dedup: hits}})
	}
	jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
	in("queued", &journal.DedupHits{}) // the first copy, queued
	jw.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: peerB, DedupKey: k, Outcome: "DROP_SILENT", Check: "prefilter",
		Row: -1, Reason: "duplicate", Via: "direct", AtOffer: true}}) // the second copy's, before its frame
	in("queued", &journal.DedupHits{Known: true, PeerRecent: true}) // seq 4: the second copy
	in("queue_full", nil)                                           // seq 5: not taken
	jw.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Peer: peerB, DedupKey: k, Outcome: "ACCEPT", Check: "PROCESS",
		Row: 3, Via: "direct"}}) // the core's, of the first copy
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	var res exportResult
	runJSON(t, fs, 0, &res, "export", "--dir", "/j", "--out", "/out", "--format", "r01")
	of := map[string]any{}
	var frames []any // seq of the received frames in order
	for _, r := range readFrames(t, fs, "/out/frames-r.jsonl") {
		switch r["type"] {
		case "outcome":
			of[r["outcome"].(string)] = r["of"]
		case "frame":
			frames = append(frames, r["seq"])
		}
	}
	if len(frames) != 3 || of["ACCEPT"] != frames[0] || of["DROP_SILENT"] != frames[1] || res.Unlinked != 0 {
		t.Fatalf("links %v, unlinked %d; frames %v: want ACCEPT of the first, DROP_SILENT of the second", of, res.Unlinked, frames)
	}
}
