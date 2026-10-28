package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// Normal open/close APIs create a genuine unused empty segment before the
// journal starts. These are metadata fixtures, not changed existing WAL data,
// injected faults, or independent runtime reconstruction evidence.
func TestBundleNormalEmptyPrefixKeepsOriginalFilesAndIdentity(t *testing.T) {
	for _, diagnostic := range []bool{false, true} {
		t.Run(map[bool]string{false: "functional", true: "diagnostic"}[diagnostic], func(t *testing.T) {
			mem := fsys.NewMem()
			empty, _, err := wal.Open(mem, "/source", wal.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err = empty.Close(); err != nil {
				t.Fatal(err)
			}
			if size, err := mem.Size("/source/00000000000000000000.wal"); err != nil || size != 0 {
				t.Fatal("normal unused segment is not empty", size, err)
			}
			id := ident()
			id.Run = "normal-after-unused-segment"
			w, err := Open(Options{FS: mem, Dir: "/source", Synchronous: true}, id)
			if err != nil {
				t.Fatal(err)
			}
			if diagnostic {
				source := minimalCoreSource(t)
				source.Head, err = codec.EncodeHeader(&types.Header{Number: types.HeightFromUint64(42), Difficulty: big.NewInt(1)})
				if err != nil {
					t.Fatal(err)
				}
				w.Put(Record{Body: source})
			} else {
				w.Put(Record{Body: step(1)})
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			original, err := ReadAll(mem, "/source")
			if err != nil {
				t.Fatal(err)
			}
			files, err := mem.ReadDir("/source")
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			manifest, err := WriteBundle(mem, "/source", &output, BundleOptions{})
			if err != nil {
				t.Fatal("normal empty prefix blocked original bundle", err)
			}
			if !manifest.StartsAtRunStart || len(manifest.Files) != len(files) || !reflect.DeepEqual(manifest.Runs, []string{id.Run}) || manifest.Node.ChainID != id.ChainID.String() {
				t.Fatal("empty prefix changed original run identity or omitted source files", manifest)
			}
			if _, err = ReadBundle(bytes.NewReader(output.Bytes()), mem, "/retained"); err != nil {
				t.Fatal(err)
			}
			restored, err := ReadAll(mem, "/retained")
			if err != nil || !reflect.DeepEqual(original, restored) {
				t.Fatal("original records changed", err)
			}
			for _, file := range manifest.Files {
				before, err := mem.ReadFile(filepath.Join("/source", file.Name))
				if err != nil {
					t.Fatal(err)
				}
				after, err := mem.ReadFile(filepath.Join("/retained", file.Name))
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(before)
				if !bytes.Equal(before, after) || file.Size != int64(len(before)) || file.SHA256 != hex.EncodeToString(digest[:]) {
					t.Fatal("original empty or populated file changed", file.Name)
				}
			}
			t.Logf("normal_empty_prefix_retained=true diagnostic=%t original_records=%d files=%d", diagnostic, len(original), len(files))
		})
	}
}

// Generic WAL APIs can store valid frames without a journal identity. Such
// local metadata is not a qualified journal, even after another real writer.
// No existing WAL bytes, packet, signature or node state is modified.
func TestBundleDoesNotInferHeaderlessIdentity(t *testing.T) {
	for _, prefix := range []bool{true, false} {
		t.Run(map[bool]string{true: "prefix", false: "suffix"}[prefix], func(t *testing.T) {
			mem := fsys.NewMem()
			writeJournal := func() {
				t.Helper()
				w, err := Open(Options{FS: mem, Dir: "/source", Synchronous: true}, ident())
				if err != nil {
					t.Fatal(err)
				}
				w.Put(Record{Body: step(1)})
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !prefix {
				writeJournal()
			}
			encoded, err := encodeBody(Record{Body: step(1)}, 1)
			if err != nil {
				t.Fatal(err)
			}
			generic, _, err := wal.Open(mem, "/source", wal.Options{Header: func() []wal.Record { return []wal.Record{{Format: Format, Kind: uint8(KindStep), Body: encoded}} }})
			if err != nil {
				t.Fatal(err)
			}
			if err = generic.Close(); err != nil {
				t.Fatal(err)
			}
			if prefix {
				writeJournal()
			}
			var output bytes.Buffer
			if manifest, err := WriteBundle(mem, "/source", &output, BundleOptions{}); err == nil || manifest != nil || output.Len() != 0 {
				t.Fatal("nonempty headerless source acquired inferred identity", manifest, err)
			}
		})
	}
}
