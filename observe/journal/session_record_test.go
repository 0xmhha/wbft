package journal

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestSessionRecordQualifiedAndUnavailableRoundTrip(t *testing.T) {
	for _, ref := range []*SessionRef{nil, {Run: "original-writer", Ordinal: ^uint64(0)}} {
		for _, event := range []string{SessionObserved, string(transport.SessionWriterEnded), string(transport.SessionRemoved)} {
			r := &SessionRec{Session: ref, Event: event, Active: event == SessionObserved, Mono: 17 * time.Second, WallNs: 30000000001}
			raw, err := encodeBody(Record{Body: r}, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeBody(KindSession, raw)
			if err != nil || !reflect.DeepEqual(decoded.Body, r) || decoded.JSeq != ^uint64(0) {
				t.Fatal(decoded, err)
			}
			again, err := encodeBody(decoded, decoded.JSeq)
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("session observation changed", err)
			}
			if monoOf(decoded) != r.Mono || size(decoded) < int64(160+len(event)) {
				t.Fatal("queue accounting omitted session metadata")
			}
		}
	}
	// A callback may first observe a lifetime after it has ended. It must not
	// fabricate an attach or an active session in that case.
	if _, err := encodeBody(Record{Body: &SessionRec{Event: SessionObserved}}, 2); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRecordStrictLocalCodec(t *testing.T) {
	// These are codec-only shape tests, never packets sent to a network peer.
	base := sessionRLP{Format: Format, JSeq: 2, Event: SessionObserved, Active: 1, Session: []sessionRefRLP{{Profile: 1, Run: "writer", Ordinal: 1}}}
	for _, mutate := range []func(*sessionRLP){
		func(w *sessionRLP) { w.Format++ },
		func(w *sessionRLP) { w.Active = 2 },
		func(w *sessionRLP) { w.Event = "attached" },
		func(w *sessionRLP) { w.Event = string(transport.SessionRemoved) },
		func(w *sessionRLP) { w.Session[0].Profile++ },
		func(w *sessionRLP) { w.Session[0].Run = "" },
		func(w *sessionRLP) { w.Session[0].Ordinal = 0 },
		func(w *sessionRLP) { w.Session = append(w.Session, w.Session[0]) },
	} {
		w := base
		w.Session = append([]sessionRefRLP(nil), base.Session...)
		mutate(&w)
		raw, err := rlp.Encode(&w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindSession, raw); err == nil {
			t.Fatal("invalid session record accepted", w)
		}
	}
	for _, ref := range []*SessionRef{{}, {Run: "writer"}, {Ordinal: 1}} {
		if _, err := encodeBody(Record{Body: &SessionRec{Session: ref, Event: SessionObserved}}, 2); err == nil {
			t.Fatal("partial session reference encoded")
		}
	}
}

func TestSessionFrameReferenceTailPreservesLegacyBytes(t *testing.T) {
	normal := deferredNormalMessage(t)
	original := &MsgRec{Dir: In, Code: uint64(normal.Code), Payload: normal.Payload, Capture: 9}
	before, err := encodeBody(Record{Body: original}, 2)
	if err != nil {
		t.Fatal(err)
	}
	var legacy msgRLP
	if err := rlp.DecodeStrict(before, &legacy); err != nil {
		t.Fatal(err)
	}
	if len(legacy.Session) != 0 {
		t.Fatal("legacy acquired session provenance")
	}
	for _, ordinal := range []uint64{(1 << 53) + 1, ^uint64(0)} {
		m := *original
		m.Session = &SessionRef{Run: "original-writer", Ordinal: ordinal}
		raw, err := encodeBody(Record{Body: &m}, 3)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindMsg, raw)
		if err != nil || !reflect.DeepEqual(decoded.Body, &m) {
			t.Fatal("raw source or normal signed bytes changed", decoded, err)
		}
		if size(Record{Body: &m})-size(Record{Body: original}) != 48+int64(len(m.Session.Run)) {
			t.Fatal("session tail not included in queue bytes")
		}
	}
	after, err := encodeBody(Record{Body: original}, 2)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("nil session changed original bytes", err)
	}
	legacy.Session = []sessionRefRLP{{Profile: 1, Run: "writer"}}
	raw, err := rlp.Encode(&legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBody(KindMsg, raw); err == nil {
		t.Fatal("partial raw source silently downgraded to legacy")
	}
}

func TestSessionRecordJournalRetainsOriginalRunAcrossRotation(t *testing.T) {
	fs := fsys.NewMem()
	id := ident()
	id.Run = "current-writer"
	w, err := Open(Options{FS: fs, Dir: "/sessions", Synchronous: true, SegmentBytes: 1024}, id)
	if err != nil {
		t.Fatal(err)
	}
	ref := &SessionRef{Run: "original-writer", Ordinal: (1 << 53) + 1}
	normal := deferredNormalMessage(t)
	w.Put(Record{Body: &SessionRec{Session: ref, Peer: normal.Peer, Event: SessionObserved, Active: true, Mono: time.Second}})
	for i := 0; i < 20; i++ {
		w.Put(Record{Body: &MsgRec{Session: ref, Dir: In, Code: uint64(normal.Code), Payload: normal.Payload, Capture: uint64(i + 1)}})
	}
	w.Put(Record{Body: &SessionRec{Session: ref, Peer: normal.Peer, Event: string(transport.SessionRemoved), Mono: 2 * time.Second}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/sessions")
	if err != nil {
		t.Fatal(err)
	}
	segments, sessions, messages := 0, 0, 0
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			segments++
			if r.Run != id.Run {
				t.Fatal("current writer identity changed")
			}
		case *SessionRec:
			sessions++
			if !reflect.DeepEqual(r.Session, ref) {
				t.Fatal("original session lost across rotation")
			}
		case *MsgRec:
			messages++
			if !reflect.DeepEqual(r.Session, ref) || !bytes.Equal(r.Payload, normal.Payload) {
				t.Fatal("original raw frame changed")
			}
		}
	}
	if segments < 2 || sessions != 2 || messages != 20 {
		t.Fatal("missing rotated records", segments, sessions, messages)
	}
}

func TestSessionRecordQueueBudgetReportsMissingSourceByKind(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/session-gap", QueueRecords: 8, QueueBytes: 50}, ident())
	if err != nil {
		t.Fatal(err)
	}
	mono := 19 * time.Second
	w.Put(Record{Body: &SessionRec{Event: SessionObserved, Active: true, Mono: mono}})
	w.Put(Record{Body: &MsgRec{Dir: In, Mono: mono, Session: &SessionRef{Run: "original-writer", Ordinal: 1}}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/session-gap")
	if err != nil {
		t.Fatal(err)
	}
	dropped := map[uint64]uint64{}
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			if gap.FirstMono != mono || gap.LastMono != mono {
				t.Fatal("missing source clock was lost", gap)
			}
			for _, kind := range gap.ByKind {
				dropped[kind.Kind] += kind.Count
			}
		}
	}
	if dropped[uint64(KindSession)] != 1 || dropped[uint64(KindMsg)] != 1 {
		t.Fatal("missing session or raw frame was not reported", dropped)
	}
}
