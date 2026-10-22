package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
	"strconv"
	"time"
)

type cacheCoordinate struct{ instance, sequence uint64 }
type indexedCacheOperation struct {
	seq      uint64
	position wal.Position
	record   *journal.CacheRec
}
type cacheInstance struct {
	declared bool
	last     uint64
}
type cacheRun struct {
	peers                                       map[uint32]types.Address
	peerIndices                                 map[types.Address]uint32
	node                                        types.Address
	version, declaration, instances, operations uint64
	complete                                    bool
	caches                                      map[uint64]*cacheInstance
	ops                                         map[cacheCoordinate]indexedCacheOperation
	attempts                                    map[[2]uint64]bool
}

func (w *r01Writer) indexCache(rec journal.Record, pos wal.Position) {
	if w.cacheErr != nil {
		return
	}
	if _, write := rec.Body.(*journal.WriteCacheRec); write {
		w.cacheErr = fmt.Errorf("completed-write cache observations are unavailable in R01 exports")
		return
	}
	if _, ok := rec.Body.(*journal.ReceiveCacheRec); ok {
		w.cacheErr = fmt.Errorf("accepted-receive cache observations are unavailable in R01 exports")
		return
	}
	if s, ok := rec.Body.(*journal.SegmentRec); ok {
		if s.Core.CachePolicy != nil {
			w.cacheErr = fmt.Errorf("accepted/completed cache profile is unavailable in R01 exports")
			return
		}
		if w.cache == nil {
			w.cache = map[string]*cacheRun{}
		}
		old := w.cache[s.Run]
		if w.cacheRun != s.Run && old != nil && (old.version != 0 || s.Core.CacheTrace != 0) {
			w.cacheErr = fmt.Errorf("cache writer run reappeared")
			return
		}
		w.cacheRun = s.Run
		if old != nil {
			if (old.version != 0 || s.Core.CacheTrace != 0) && (old.node != s.Self || old.version != s.Core.CacheTrace) {
				w.cacheErr = fmt.Errorf("cache source identity changed")
			}
			return
		}
		if s.Core.CacheTrace > journal.CacheTraceVersion {
			w.cacheErr = fmt.Errorf("unsupported cache trace version")
			return
		}
		w.cache[s.Run] = &cacheRun{node: s.Self, version: s.Core.CacheTrace, declaration: rec.JSeq, complete: true, caches: map[uint64]*cacheInstance{}, ops: map[cacheCoordinate]indexedCacheOperation{}, attempts: map[[2]uint64]bool{}, peers: map[uint32]types.Address{}, peerIndices: map[types.Address]uint32{}}
		return
	}
	c := w.cache[w.cacheRun]
	if c == nil || c.version == 0 {
		switch b := rec.Body.(type) {
		case *journal.CacheRec:
			w.cacheErr = fmt.Errorf("cache operation has no trace capability")
		case *journal.MsgRec:
			if b.Attempt != nil {
				w.cacheErr = fmt.Errorf("send attempt has no trace capability")
			}
		case *journal.SuppressedRec:
			if b.Cache != 0 || b.Operation != 0 {
				w.cacheErr = fmt.Errorf("suppressed decision has no trace capability")
			}
		}
		return
	}
	switch b := rec.Body.(type) {
	case *journal.PeerRec:
		if old, ok := c.peers[b.PeerIdx]; ok && old != b.Addr {
			w.cacheErr = fmt.Errorf("cache peer index changed identity")
			return
		}
		if old, ok := c.peerIndices[b.Addr]; ok && old != b.PeerIdx {
			w.cacheErr = fmt.Errorf("cache peer address has multiple indices")
			return
		}
		c.peers[b.PeerIdx], c.peerIndices[b.Addr] = b.Addr, b.PeerIdx
	case *journal.GapRec:
		c.complete = false
	case *journal.CacheRec:
		x := c.caches[b.Instance]
		if x == nil {
			x = &cacheInstance{}
			c.caches[b.Instance] = x
		}
		if b.Action == "begin" {
			if x.declared || b.Self != c.node {
				w.cacheErr = fmt.Errorf("duplicate or foreign cache declaration")
				return
			}
			if x.last != 0 {
				c.complete = false
			}
			x.declared = true
			c.instances++
			return
		}
		key := cacheCoordinate{b.Instance, b.Sequence}
		if _, ok := c.ops[key]; ok {
			w.cacheErr = fmt.Errorf("duplicate cache operation sequence")
			return
		}
		if !x.declared || b.Sequence != x.last+1 {
			c.complete = false
		}
		x.last = b.Sequence
		c.operations++
		c.ops[key] = indexedCacheOperation{rec.JSeq, pos, b}
	case *journal.MsgRec:
		if b.Attempt == nil {
			return
		}
		if b.Dir != journal.Out {
			w.cacheErr = fmt.Errorf("received frame contains a send attempt")
			return
		}
		key := [2]uint64{b.Attempt.Sequence, uint64(b.PeerIdx)}
		if c.attempts[key] {
			w.cacheErr = fmt.Errorf("duplicate send attempt for peer")
			return
		}
		c.attempts[key] = true
	}
}

func (w *r01Writer) hasCacheEvidence() bool {
	for _, c := range w.cache {
		if c.version != 0 {
			return true
		}
	}
	return false
}
func (w *r01Writer) currentCache() *cacheRun {
	if w.run == nil {
		return nil
	}
	c := w.cache[w.run.Run]
	if c == nil || c.version == 0 {
		return nil
	}
	return c
}
func cacheNumber(n uint64) string { return strconv.FormatUint(n, 10) }
func cacheAddressList(a []types.Address) []string {
	out := make([]string, len(a))
	for i, p := range a {
		out[i] = hexAddr(p)
	}
	return out
}

// The complete mutation context remains outside the requested height filter.
// Declaration clocks are unavailable; only actual operations carry clocks.
func (w *r01Writer) cacheRecord(rec journal.Record, pos wal.Position) error {
	c := w.currentCache()
	if c == nil {
		return nil
	}
	r := map[string]any{"v": r01Version, "node": hexAddr(c.node), "run": w.run.Run, "seq": rec.JSeq, "journal_segment": pos.Segment, "journal_offset": pos.Offset}
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if scheduler := w.scheduler[w.run.Run]; scheduler != nil && scheduler.version != 0 {
			return nil
		}
		if rec.JSeq != c.declaration {
			return nil
		}
		r["type"], r["t_wall"], r["t_mono_ns"], r["clock_source"] = "cache_trace", time.Unix(0, 0).UTC().Format(time.RFC3339Nano), int64(0), "unavailable"
		r["cache_trace"] = cacheTraceMetadata(c)
		w.addSyncTrace(r, rec.JSeq)
	case *journal.CacheRec:
		if b.Action == "begin" {
			r["type"], r["t_wall"], r["t_mono_ns"], r["clock_source"] = "cache_instance", time.Unix(0, 0).UTC().Format(time.RFC3339Nano), int64(0), "unavailable"
			r["cache_instance"] = map[string]any{"instance": cacheNumber(b.Instance), "self": hexAddr(b.Self), "peer_capacity": cacheNumber(b.PeerCapacity), "message_capacity": cacheNumber(b.MessageCapacity), "initial_state": "empty"}
		} else {
			r["type"], r["t_wall"], r["t_mono_ns"] = "cache_operation", time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano), int64(b.Mono)
			r["cache_operation"] = map[string]any{"instance": cacheNumber(b.Instance), "sequence": cacheNumber(b.Sequence), "action": b.Action, "peer": hexAddr(b.Peer), "code": fmt.Sprintf("%#x", b.Code), "dedup_key": hexHash(b.Key), "payload_sha256": hex.EncodeToString(b.PayloadSHA256[:]), "cause": b.Cause, "known_hit": b.Known, "peer_recent_hit": b.Recent, "candidates_available": b.Available, "candidates": cacheAddressList(b.Candidates), "targets": cacheAddressList(b.Targets), "suppressed": cacheAddressList(b.Suppressed)}
		}
	default:
		return nil
	}
	return w.write(r)
}

func cacheSourceMetadata(c *cacheRun, instance, operation uint64) map[string]any {
	m := map[string]any{"instance": cacheNumber(instance), "operation": cacheNumber(operation), "source_available": false}
	x, ok := c.ops[cacheCoordinate{instance, operation}]
	if !ok || !c.complete {
		return m
	}
	m["source_available"], m["source_seq"], m["source_segment"], m["source_offset"] = true, cacheNumber(x.seq), cacheNumber(x.position.Segment), strconv.FormatInt(x.position.Offset, 10)
	return m
}
func (w *r01Writer) cacheFrame(seq uint64, b *journal.MsgRec, pos wal.Position, r map[string]any) error {
	c := w.currentCache()
	if c == nil {
		return nil
	}
	r["journal_segment"], r["journal_offset"] = pos.Segment, pos.Offset
	if b.Dir != journal.Out {
		return nil
	}
	m := map[string]any{"available": false}
	r["send_attempt"] = m
	if b.Attempt == nil {
		return nil
	}
	a := b.Attempt
	m["available"], m["sequence"] = true, cacheNumber(a.Sequence)
	if a.Cache == 0 {
		m["cache_source_available"] = false
		return nil
	}
	ref := cacheSourceMetadata(c, a.Cache, a.Operation)
	m["cache_decision"] = ref
	x, ok := c.ops[cacheCoordinate{a.Cache, a.Operation}]
	if !ok {
		return nil
	}
	op := x.record
	code := op.Code
	if code < transport.CodeFirst || code > transport.CodeLast {
		code = transport.CodeLegacy
	}
	sum := sha256.Sum256(b.Payload)
	if op.Action != "gossip" || codec.DedupKey(b.Payload) != b.DedupKey || op.Key != b.DedupKey || op.PayloadSHA256 != types.Hash(sum) || code != b.Code || op.Cause != b.Cause || x.seq >= seq {
		return fmt.Errorf("send attempt does not match its cache decision")
	}
	// A peer listed as suppressed is deliberately retained. The independent
	// checker must report an actual write of that decision as a violation.
	return nil
}
func (w *r01Writer) cacheSuppressed(b *journal.SuppressedRec, r map[string]any) error {
	c := w.currentCache()
	if c == nil || b.Cache == 0 {
		return nil
	}
	r["cache_decision"] = cacheSourceMetadata(c, b.Cache, b.Operation)
	r["clock_source"] = "unavailable"
	x, ok := c.ops[cacheCoordinate{b.Cache, b.Operation}]
	if !ok {
		return nil
	}
	if x.record.Action != "gossip" || x.record.Key != b.DedupKey || x.record.Cause != b.Cause {
		return fmt.Errorf("suppression does not match its cache decision")
	}
	return nil
}

func cacheTraceMetadata(c *cacheRun) map[string]any {
	return map[string]any{"version": cacheNumber(c.version), "instances": cacheNumber(c.instances), "operations": cacheNumber(c.operations), "complete": c.complete}
}
