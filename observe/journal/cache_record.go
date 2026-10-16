package journal

import (
	"fmt"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"time"
)

const CacheTraceVersion uint64 = 1

// CacheRec is either an empty-cache declaration (no clock) or a mutation
// observed under its actual mutex. The instance lives within one writer run.
type CacheRec struct {
	Instance, Sequence              uint64
	Action                          string
	Self, Peer                      types.Address
	PeerCapacity, MessageCapacity   uint64
	Code                            uint64
	Key, PayloadSHA256              types.Hash
	Cause                           event.SendCause
	Known, Recent, Available        bool
	Candidates, Targets, Suppressed []types.Address
	Mono                            time.Duration
	WallNs                          int64
}
type cacheRLP struct {
	Format, JSeq, Instance, Sequence    uint64
	Action                              string
	Self, Peer                          types.Address
	PeerCapacity, MessageCapacity, Code uint64
	Key, PayloadSHA256                  types.Hash
	Cause                               string
	Known, Recent, Available            uint64
	Candidates, Targets, Suppressed     []types.Address
	Mono, WallNs                        uint64
}

func validCacheRec(r *CacheRec) bool {
	if r.Instance == 0 || r.Mono < 0 {
		return false
	}
	if r.Action == "begin" {
		return r.Sequence == 0 && r.Self != (types.Address{}) && r.Peer == (types.Address{}) && r.PeerCapacity > 0 && r.MessageCapacity > 0 && r.Code == 0 && r.Key == (types.Hash{}) && r.PayloadSHA256 == (types.Hash{}) && r.Cause == "" && !r.Known && !r.Recent && !r.Available && len(r.Candidates) == 0 && len(r.Targets) == 0 && len(r.Suppressed) == 0 && r.Mono == 0 && r.WallNs == 0
	}
	if r.Sequence == 0 || r.Self != (types.Address{}) || r.PeerCapacity != 0 || r.MessageCapacity != 0 || r.Key == (types.Hash{}) || r.PayloadSHA256 == (types.Hash{}) {
		return false
	}
	switch r.Action {
	case "inbound":
		return r.Cause == "" && !r.Available && len(r.Candidates) == 0 && len(r.Targets) == 0 && len(r.Suppressed) == 0
	case "gossip":
		return r.Peer == (types.Address{}) && !r.Recent
	default:
		return false
	}
}
func encodeCacheRec(r *CacheRec, jseq uint64) ([]byte, error) {
	if !validCacheRec(r) {
		return nil, fmt.Errorf("journal: invalid cache operation")
	}
	return rlp.Encode(&cacheRLP{Format: Format, JSeq: jseq, Instance: r.Instance, Sequence: r.Sequence, Action: r.Action, Self: r.Self, Peer: r.Peer, PeerCapacity: r.PeerCapacity, MessageCapacity: r.MessageCapacity, Code: r.Code, Key: r.Key, PayloadSHA256: r.PayloadSHA256, Cause: string(r.Cause), Known: boolUint(r.Known), Recent: boolUint(r.Recent), Available: boolUint(r.Available), Candidates: cacheAddresses(r.Candidates), Targets: cacheAddresses(r.Targets), Suppressed: cacheAddresses(r.Suppressed), Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}
func decodeCacheRec(body []byte) (Record, error) {
	var w cacheRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: cache: %v", ErrRecord, err)
	}
	r := &CacheRec{Instance: w.Instance, Sequence: w.Sequence, Action: w.Action, Self: w.Self, Peer: w.Peer, PeerCapacity: w.PeerCapacity, MessageCapacity: w.MessageCapacity, Code: w.Code, Key: w.Key, PayloadSHA256: w.PayloadSHA256, Cause: event.SendCause(w.Cause), Known: w.Known == 1, Recent: w.Recent == 1, Available: w.Available == 1, Candidates: w.Candidates, Targets: w.Targets, Suppressed: w.Suppressed, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}
	if w.Format != Format || w.Known > 1 || w.Recent > 1 || w.Available > 1 || !validCacheRec(r) {
		return Record{}, fmt.Errorf("%w: invalid cache operation", ErrRecord)
	}
	return Record{Kind: KindCache, JSeq: w.JSeq, Body: r}, nil
}
func cacheAddresses(a []types.Address) []types.Address {
	if a == nil {
		return []types.Address{}
	}
	return a
}
