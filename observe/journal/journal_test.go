package journal

import (
	"bytes"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func ident() Identity {
	return Identity{Self: types.Address{1}, Run: "run-1", ChainID: big.NewInt(8282), Mode: "standalone",
		Core: CoreOptions{ChainConfig: []byte(`{"chainId":1}`), Self: types.Address{1}, Improvements: 1, BacklogLimit: 88, Profile: "compat"}}
}

func step(i uint64) *StepRec {
	return &StepRec{EngineRun: 1, Step: i, Mono: time.Duration(i) * time.Millisecond, WallNs: int64(1_000 + i), InputKind: "message",
		Input: bytes.Repeat([]byte{byte(i)}, 40), Via: "peer", HeadNumber: types.HeightFromUint64(i / 10), Env: [][]byte{{1, 2}},
		ValsetDigest: types.Hash{2}, OutDigest: types.Hash{byte(i)}}
}

func TestWriteReadSegments(t *testing.T) {
	for _, sync := range []bool{true, false} {
		fs := fsys.NewMem()
		opt := Options{FS: fs, Dir: "/j", SegmentBytes: 600, Synchronous: sync}
		w, err := Open(opt, ident())
		if err != nil {
			t.Fatal(err)
		}
		w.Put(Record{Body: &PeerRec{PeerIdx: 3, Addr: types.Address{3}, Event: "attached"}})
		for i := uint64(1); i <= 40; i++ {
			w.Put(Record{Body: step(i)})
			w.Put(Record{Body: &OutcomeRec{Code: 0x13, Outcome: event.Accept, Check: "PROCESS", Row: 17, Via: "direct", Step: i}})
			w.Put(Record{Body: &MsgRec{Dir: In, PeerIdx: 3, Code: 0x13, WireCode: 0x34, Payload: []byte{0xc0}, Offer: "queued"}})
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		recs, err := ReadAll(fs, "/j")
		if err != nil {
			t.Fatal(err)
		}
		segs, _ := wal.Segments(fs, "/j")
		if len(segs) < 3 {
			t.Fatalf("segments %d", len(segs))
		}
		var steps, segRecs, peers int
		var last uint64
		for _, r := range recs {
			if r.JSeq != last+1 {
				t.Fatalf("sync %v: jseq %d after %d", sync, r.JSeq, last)
			}
			last = r.JSeq
			switch b := r.Body.(type) {
			case *StepRec:
				steps++
				if want := step(b.Step); !bytes.Equal(b.Input, want.Input) || b.OutDigest != want.OutDigest || b.HeadNumber.Cmp(want.HeadNumber) != 0 {
					t.Fatalf("step %d differs", b.Step)
				}
			case *SegmentRec:
				segRecs++
				if b.Run != "run-1" || string(b.Core.ChainConfig) != `{"chainId":1}` || b.Core.Improvements != 1 {
					t.Fatalf("segment record %+v", b)
				}
			case *PeerRec:
				peers++
			case *OutcomeRec:
				if b.Row != 17 || b.Outcome != event.Accept {
					t.Fatalf("outcome %+v", b)
				}
			}
		}
		if steps != 40 || segRecs != len(segs) || peers < len(segs) {
			t.Fatalf("sync %v: steps %d segment records %d peers %d segments %d", sync, steps, segRecs, peers, len(segs))
		}
		// Every segment starts with its segment record and the attached peer.
		for _, s := range segs {
			r, _ := wal.OpenReader(fs, "/j", wal.Position{Segment: s.Index})
			a, _, _ := r.Next()
			b, _, _ := r.Next()
			if Kind(a.Kind) != KindSegment || Kind(b.Kind) != KindPeer {
				t.Fatalf("segment %d starts with %d, %d", s.Index, a.Kind, b.Kind)
			}
		}
		// Closed segments have index files.
		names, _ := fs.ReadDir("/j")
		idx := 0
		for _, n := range names {
			if strings.HasSuffix(n, indexSuffix) {
				idx++
			}
		}
		if idx != len(segs) {
			t.Fatalf("index files %d for %d segments", idx, len(segs))
		}
	}
}

func TestGapOnOverflow(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/j", QueueRecords: 1}, ident())
	if err != nil {
		t.Fatal(err)
	}
	// Hold the writer so that the queue fills.
	w.wmu.Lock()
	w.Put(Record{Body: step(1)})
	w.qmu.Lock()
	for len(w.queue) != 0 {
		w.qmu.Unlock()
		time.Sleep(time.Millisecond)
		w.qmu.Lock()
	}
	w.qmu.Unlock()
	for i := uint64(2); i <= 10; i++ {
		w.Put(Record{Body: step(i)})
	}
	w.wmu.Unlock()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	recs, _ := ReadAll(fs, "/j")
	var gaps []*GapRec
	var steps int
	for _, r := range recs {
		switch b := r.Body.(type) {
		case *GapRec:
			gaps = append(gaps, b)
		case *StepRec:
			steps++
		}
	}
	dropped := uint64(0)
	for _, g := range gaps {
		dropped += g.Dropped
	}
	if len(gaps) == 0 || int(dropped)+steps != 10 {
		t.Fatalf("gaps %v, steps %d", gaps, steps)
	}
}

func TestPrune(t *testing.T) {
	fs := fsys.NewMem()
	opt := Options{FS: fs, Dir: "/j", SegmentBytes: 400, Synchronous: true}
	w, err := Open(opt, ident())
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 30; h++ {
		w.NoteHead(types.HeightFromUint64(h))
		for i := 0; i < 3; i++ {
			w.Put(Record{Body: step(h*10 + uint64(i))})
		}
	}
	segs, _ := wal.Segments(fs, "/j")
	before := len(segs)
	cur := segs[len(segs)-1].Index
	res, err := Prune(fs, "/j", types.HeightFromUint64(30), Options{KeepHeights: 10}, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) == 0 {
		t.Fatal("nothing pruned by height")
	}
	res2, err := Prune(fs, "/j", types.HeightFromUint64(30), Options{MaxBytes: 1}, cur)
	if err != nil {
		t.Fatal(err)
	}
	segs, _ = wal.Segments(fs, "/j")
	if len(segs) != 1 || segs[0].Index != cur {
		t.Fatalf("size pruning left %d segments (before %d, removed %v %v)", len(segs), before, res.Removed, res2.Removed)
	}
	for _, s := range res2.Removed {
		if _, err := fs.ReadFile(filepath.Join("/j", s+indexSuffix)); err == nil {
			t.Fatal("index of a removed segment kept")
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// Pruning happens as the head advances with the default rules applied.
func TestPruneWhileWriting(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/j", SegmentBytes: 400, KeepHeights: 5, Synchronous: true}, ident())
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 60; h++ {
		w.NoteHead(types.HeightFromUint64(h))
		w.Put(Record{Body: step(h)})
		w.Put(Record{Body: step(h)})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Heads 55 .. 60 need about two segments each here.
	segs, _ := wal.Segments(fs, "/j")
	if len(segs) > 16 {
		t.Fatalf("%d segments kept", len(segs))
	}
	for _, s := range segs[:len(segs)-1] {
		ix, ok := readIndex(fs, "/j", s.Name)
		if !ok || ix.MaxHeight == nil || *ix.MaxHeight < "54" && len(*ix.MaxHeight) == 2 {
			t.Fatalf("segment %s kept with index %+v", s.Name, ix)
		}
	}
}

func TestTornTail(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/j", Synchronous: true}, ident())
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 5; i++ {
		w.Put(Record{Body: step(i)})
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	segs, _ := wal.Segments(fs, "/j")
	_ = fs.Corrupt(filepath.Join("/j", segs[0].Name), func(b []byte) []byte { return b[:len(b)-7] })
	recs, err := ReadAll(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1+4 {
		t.Fatalf("%d records", len(recs))
	}
}

func TestDupFirstUnsupported(t *testing.T) {
	if _, err := Open(Options{FS: fsys.NewMem(), Dir: "/j", Duplicates: DupFirst}, ident()); err != ErrUnsupported {
		t.Fatal(err)
	}
}

// TestMsgSize keeps the size of a msg record whose payload was not kept,
// and still reads a msg record written before records had a size.
func TestMsgSize(t *testing.T) {
	m := &MsgRec{Dir: In, PeerIdx: 2, Code: 0x12, WireCode: 0x12, Size: 20 << 20, Offer: "frame_disconnect"}
	body, err := encodeBody(Record{Body: m}, 7)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeBody(KindMsg, body)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Body.(*MsgRec); got.Size != 20<<20 || len(got.Payload) != 0 || r.JSeq != 7 {
		t.Fatalf("decoded %+v", got)
	}
	old, err := rlp.Encode(&msgRLPNoSize{Format: Format, JSeq: 8, Dir: Out, PeerIdx: 1, Code: 0x13, WireCode: 0x13, Payload: []byte{1, 2},
		Write: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	r, err = decodeBody(KindMsg, old)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Body.(*MsgRec); got.Size != 0 || !bytes.Equal(got.Payload, []byte{1, 2}) || got.Write != "ok" || r.JSeq != 8 {
		t.Fatalf("old record %+v", got)
	}
}

// TestMsgEngine keeps the engine state of a msg record and still reads a
// record written before records had one.
func TestMsgEngine(t *testing.T) {
	body, err := encodeBody(Record{Body: &MsgRec{Dir: In, Code: 0x12, Payload: []byte{1}, Engine: "syncing", Offer: "queued"}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeBody(KindMsg, body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Body.(*MsgRec).Engine != "syncing" {
		t.Fatalf("decoded %+v", r.Body)
	}
	old, err := rlp.Encode(&msgRLPNoEngine{Format: Format, JSeq: 4, Dir: In, Code: 0x13, Size: 20 << 20, Offer: "frame_disconnect"})
	if err != nil {
		t.Fatal(err)
	}
	r, err = decodeBody(KindMsg, old)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Body.(*MsgRec); got.Engine != "" || got.Size != 20<<20 || r.JSeq != 4 {
		t.Fatalf("record without engine %+v", got)
	}
}
