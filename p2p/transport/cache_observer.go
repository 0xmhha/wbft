package transport

import (
	"crypto/sha256"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// CacheOperation describes one real mutation under a Dedup's mutex. Its
// sequence is local to Instance; timestamps or frame order do not replace it.
// The observer must not reenter Dedup, block on I/O, or mutate the slices.
type CacheOperation struct {
	Retry                           RoundChangeRetrySource
	Instance, Sequence              uint64
	Action                          string
	Peer                            types.Address
	Code                            uint64
	Key, PayloadSHA256              types.Hash
	Cause                           event.SendCause
	Known, Recent, Available        bool
	Candidates, Targets, Suppressed []types.Address
}

// CacheObserver declares an initially empty cache and receives every mutation.
// BeginCache returns a writer-local instance, zero when tracing is unavailable.
type CacheObserver interface {
	BeginCache(self types.Address) uint64
	CacheOperation(CacheOperation)
}

// CacheSender binds the actual queue attempt or suppression to the decision.
// Without this optional interface the cache mutation is still observable, but
// physical callbacks have no exact cache-operation provenance.
type CacheSender interface {
	SendCache(peers []types.Address, code uint64, payload []byte, cause event.SendCause, instance, operation uint64) []SendResult
	SuppressedCache(peer types.Address, code uint64, payload []byte, cause event.SendCause, reason string, instance, operation uint64)
}

func payloadSHA256(payload []byte) types.Hash { return types.Hash(sha256.Sum256(payload)) }

func (d *Dedup) recordCache(op CacheOperation) uint64 {
	if d.cacheObserver == nil || d.cacheInstance == 0 {
		return 0
	}
	d.cacheSequence++
	op.Instance, op.Sequence = d.cacheInstance, d.cacheSequence
	d.cacheObserver.CacheOperation(op)
	return op.Sequence
}
