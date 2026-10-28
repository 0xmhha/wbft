package journal

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// These are explicit range-selection metadata models, not independently
// verified core executions, signatures, network captures or replay evidence.
func TestBundleCoreSourceHeadsKeepOriginalRecordsAndExactRange(t *testing.T) {
	mem := fsys.NewMem()
	w, err := Open(Options{FS: mem, Dir: "/source", Synchronous: true, SegmentBytes: 350}, ident())
	if err != nil {
		t.Fatal(err)
	}
	// A heightless prefix/suffix must not disappear from an unbounded export.
	w.Put(Record{Body: &SyncRec{Stage: "requested", Request: 1, Syncing: true}})
	heads := []uint64{0, (1 << 53) + 1, (1 << 53) + 2}
	for i, height := range heads {
		source := minimalCoreSource(t)
		source.Step = uint64(i + 1)
		source.Head, err = codec.EncodeHeader(&types.Header{Number: types.HeightFromUint64(height), Difficulty: big.NewInt(1)})
		if err != nil {
			t.Fatal(err)
		}
		w.Put(Record{Body: source})
	}
	for request := uint64(2); request <= 8; request++ {
		w.Put(Record{Body: &SyncRec{Stage: "requested", Request: request, Syncing: true}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var whole bytes.Buffer
	manifest, err := WriteBundle(mem, "/source", &whole, BundleOptions{})
	if err != nil || manifest.Heights.FirstHead != "0" || manifest.Heights.LastHead != "9007199254740994" || !manifest.StartsAtRunStart {
		t.Fatal("original encoded source heads were not selected exactly", manifest, err)
	}
	if _, err := ReadBundle(bytes.NewReader(whole.Bytes()), mem, "/whole"); err != nil {
		t.Fatal(err)
	}
	original, err := ReadAll(mem, "/source")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ReadAll(mem, "/whole")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, restored) {
		t.Fatal("unbounded export changed source records", len(original), len(restored))
	}
	from, to := types.HeightFromUint64((1<<53)+2), types.HeightFromUint64((1<<53)+2)
	var bounded bytes.Buffer
	selected, err := WriteBundle(mem, "/source", &bounded, BundleOptions{From: &from, To: &to})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Heights.FirstHead != "9007199254740993" || selected.Heights.LastHead != "9007199254740993" || selected.StartsAtRunStart {
		t.Fatal("explicit source range lost exact height/segment selection", selected)
	}
	if _, err := ReadBundle(bytes.NewReader(bounded.Bytes()), mem, "/bounded"); err != nil {
		t.Fatal(err)
	}
	boundedRows, err := ReadAll(mem, "/bounded")
	if err != nil {
		t.Fatal(err)
	}
	sources := 0
	for _, row := range boundedRows {
		if source, ok := row.Body.(*CoreStepRec); ok {
			sources++
			head, err := codec.DecodeHeader(source.Head)
			if err != nil || head.Number.CmpUint64((1<<53)+1) != 0 {
				t.Fatal("bounded export rewrote or included another source head", err)
			}
		}
	}
	if sources != 1 {
		t.Fatal("bounded export fabricated source steps", sources)
	}
}

func TestBundleMissingCoreSourceHeadDoesNotInventHeight(t *testing.T) {
	mem := fsys.NewMem()
	w, err := Open(Options{FS: mem, Dir: "/missing", Synchronous: true}, ident())
	if err != nil {
		t.Fatal(err)
	}
	source := minimalCoreSource(t)
	source.Unavailable = "head_encoding"
	w.Put(Record{Body: source})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := WriteBundle(mem, "/missing", &output, BundleOptions{}); err == nil || output.Len() != 0 {
		t.Fatal("missing original head became a zero-height successful bundle", err)
	}
}
