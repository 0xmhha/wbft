package journal

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
	"testing"
)

func TestCacheRecordDeclarationAndStrictOperation(t *testing.T) {
	decl := &CacheRec{Instance: 1, Action: "begin", Self: types.Address{1}, PeerCapacity: 40, MessageCapacity: 1024}
	op := &CacheRec{Instance: 1, Sequence: 3, Action: "gossip", Code: 0x13, Key: types.Hash{1}, PayloadSHA256: types.Hash{2}, Available: true, Candidates: []types.Address{{2}}, Targets: []types.Address{{2}}, Mono: 7, WallNs: 99}
	for _, r := range []*CacheRec{decl, op} {
		raw, err := encodeBody(Record{Body: r}, 8)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindCache, raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := encodeBody(decoded, 8)
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatal("cache bytes changed", err)
		}
	}
	for _, change := range []func(*CacheRec){func(r *CacheRec) { r.Mono = 1 }, func(r *CacheRec) { r.Sequence = 1 }, func(r *CacheRec) { r.PeerCapacity = 0 }} {
		bad := *decl
		change(&bad)
		if _, err := encodeBody(Record{Body: &bad}, 8); err == nil {
			t.Fatal("invalid declaration encoded", bad)
		}
	}
	raw, err := encodeBody(Record{Body: op}, 8)
	if err != nil {
		t.Fatal(err)
	}
	var wire cacheRLP
	if err = rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*cacheRLP){func(r *cacheRLP) { r.Known = 2 }, func(r *cacheRLP) { r.Recent = 2 }, func(r *cacheRLP) { r.Available = 2 }, func(r *cacheRLP) { r.Sequence = 0 }, func(r *cacheRLP) { r.Action = "guess" }, func(r *cacheRLP) { r.Format = 2 }, func(r *cacheRLP) { r.Mono = ^uint64(0) }, func(r *cacheRLP) { r.Key = types.Hash{} }, func(r *cacheRLP) { r.PayloadSHA256 = types.Hash{} }} {
		bad := wire
		change(&bad)
		b, err := rlp.Encode(&bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeBody(KindCache, b); err == nil {
			t.Fatal("invalid operation accepted", bad)
		}
	}
}

func TestCacheMetadataRespectsBoundedJournalQueue(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/cache", QueueRecords: 10, QueueBytes: 150}, ident())
	if err != nil {
		t.Fatal(err)
	}
	w.Put(Record{Body: &CacheRec{Instance: 1, Action: "begin", Self: types.Address{1}, PeerCapacity: 40, MessageCapacity: 1024}})
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	rs, err := ReadAll(fs, "/cache")
	if err != nil {
		t.Fatal(err)
	}
	var dropped uint64
	for _, r := range rs {
		if g, ok := r.Body.(*GapRec); ok {
			dropped += g.Dropped
		}
		if _, ok := r.Body.(*CacheRec); ok {
			t.Fatal("cache exceeded queue budget without gap")
		}
	}
	if dropped != 1 {
		t.Fatal("missing cache overflow evidence", dropped)
	}
}
