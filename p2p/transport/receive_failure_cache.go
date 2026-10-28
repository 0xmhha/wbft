package transport

import (
	"errors"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// ReceiveFailureProfile names the opt-in functional local failure cache.
// It is separate from diagnostic format versions and replay capabilities.
const ReceiveFailureProfile = "scoped_failure_v1"

// ReceiveFailureClass is a failed verification phase, never signer authority.
type ReceiveFailureClass uint8

const (
	ReceiveSignatureFailure ReceiveFailureClass = iota + 1
	ReceiveMembershipFailure
)

// ReceiveFailurePhase contains only canonical running publication phases.
// It retains no caller-supplied phase string or other variable-size text.
type ReceiveFailurePhase uint8

const (
	ReceiveFailureStart ReceiveFailurePhase = iota + 1
	ReceiveFailureStep
	ReceiveFailureReplay
)

// ReceiveFailureSource identifies the original local worker check. These
// diagnostic coordinates do not grant functional ownership or authority.
type ReceiveFailureSource struct {
	EngineRun, SnapshotStep, WorkerRequest uint64
	SnapshotPhase                          ReceiveFailurePhase
	SnapshotHash                           types.Hash
}

// ReceiveFailureRef names an original retained failure within one cache.
// An empty run or zero coordinates are unavailable, not references to another
// cache or run. The observer's namespace is frozen at construction.
type ReceiveFailureRef struct {
	Run             string
	Cache, Sequence uint64
}

// ReceiveFailureContext is an opaque cache-owned publication lifetime, bound
// to the accepted receiver's validation scope. Replacing it never closes the
// borrowed validation scope.
type ReceiveFailureContext struct {
	owner *ReceiveFailureCache
	scope *ValidationScope
	id    uint64
}

type receiveFailureEntry struct {
	class  ReceiveFailureClass
	ref    ReceiveFailureRef
	source ReceiveFailureSource
}

// ReceiveFailureHit is a prior failure, not a fresh Recover or core ACCEPT.
type ReceiveFailureHit struct {
	Class     ReceiveFailureClass
	Lookup    ReceiveFailureRef
	Reference ReceiveFailureRef
	Source    ReceiveFailureSource
}

// ReceiveFailureEvent records a cache operation after its mutex is released.
// Source is the current operation; Original is the retained check on a hit.
// Sequence preserves original mutex order even if delivery is reordered.
type ReceiveFailureEvent struct {
	Run                              string
	Cache, Sequence, Context         uint64
	RequestedRun                     string
	RequestedCache, RequestedContext uint64
	Action                           string
	Source, Original                 ReceiveFailureSource
	Reference                        ReceiveFailureRef
	Code                             uint64
	Payload                          types.Hash
	Class                            ReceiveFailureClass
	Before, After, Capacity          uint64
	Active, Hit, Stored              bool
	Closed                           bool
	Unavailable                      string
}

type ReceiveFailureObserver interface{ ObserveReceiveFailure(ReceiveFailureEvent) }

// ReceiveFailureOptions require an explicit entry limit. The limit bounds
// retained keys, not process heap, message sizes, or verification CPU.
type ReceiveFailureOptions struct {
	Entries uint64
	Trace   ReceiveFailureObserver
}

// ReceiveFailureCache is a separate bounded LRU of classified failures.
// Only the receiver may Record, after actual verification in the exact
// context. This primitive does not authenticate inputs or enable a policy.
type ReceiveFailureCache struct {
	mu                sync.Mutex
	opt               ReceiveFailureOptions
	id, sequence      uint64
	run               string
	exhausted, closed bool
	current           *ReceiveFailureContext
	entries           *lru[writeKey, receiveFailureEntry]
}

func NewReceiveFailureCache(opt ReceiveFailureOptions) (*ReceiveFailureCache, error) {
	if opt.Entries == 0 || opt.Entries > InmemoryMessages {
		return nil, errors.New("transport: receive failure cache requires positive entries within the message cache limit")
	}
	cache := &ReceiveFailureCache{opt: opt, id: nextObservationID(), entries: newLRU[writeKey, receiveFailureEntry](int(opt.Entries))}
	if source, ok := opt.Trace.(interface{ CaptureRun() string }); ok {
		cache.run = source.CaptureRun()
	}
	return cache, nil
}

func (c *ReceiveFailureCache) countLocked() uint64 {
	if c.entries == nil {
		return 0
	}
	return uint64(c.entries.Len())
}

func (c *ReceiveFailureCache) eventLocked(action string, source ReceiveFailureSource) ReceiveFailureEvent {
	if !c.exhausted {
		if c.sequence == ^uint64(0) {
			c.exhausted = true
		} else {
			c.sequence++
		}
	}
	e := ReceiveFailureEvent{Run: c.run, Cache: c.id, Sequence: c.sequence, Action: action, Source: source, Before: c.countLocked(), Capacity: c.opt.Entries}
	if c.exhausted || c.id == 0 {
		e.Sequence, e.Unavailable = 0, "metadata_exhausted"
	}
	if e.Unavailable == "" && c.run == "" {
		e.Unavailable = "namespace_unavailable"
	}
	if e.Unavailable == "" && (action == "context" || action == "record" || action == "lookup") {
		if source.EngineRun == 0 || source.SnapshotHash == (types.Hash{}) || source.SnapshotPhase < ReceiveFailureStart || source.SnapshotPhase > ReceiveFailureReplay {
			e.Unavailable = "snapshot_source_unavailable"
		} else if action != "context" && source.WorkerRequest == 0 {
			e.Unavailable = "worker_source_unavailable"
		}
	}
	if c.current != nil {
		e.Context = c.current.id
	}
	return e
}

func (c *ReceiveFailureCache) publishUnlock(e ReceiveFailureEvent) {
	e.After, e.Closed = c.countLocked(), c.closed
	c.mu.Unlock()
	if c.opt.Trace != nil {
		c.opt.Trace.ObserveReceiveFailure(e)
	}
}

func (c *ReceiveFailureCache) validLocked(context *ReceiveFailureContext) bool {
	return !c.closed && context != nil && context.owner == c && c.current == context && context.scope.Active()
}

// BeginContext replaces the publication lifetime and clears all prior keys.
// A nil or closed validation scope invalidates the prior context too.
func (c *ReceiveFailureCache) BeginContext(scope *ValidationScope, source ReceiveFailureSource) *ReceiveFailureContext {
	c.mu.Lock()
	e := c.eventLocked("context", source)
	c.current, c.entries = nil, nil
	if !c.closed && scope.Active() {
		c.entries = newLRU[writeKey, receiveFailureEntry](int(c.opt.Entries))
		c.current = &ReceiveFailureContext{owner: c, scope: scope, id: e.Sequence}
	}
	context := c.current
	if context != nil {
		e.Context, e.Active = context.id, true
	}
	c.publishUnlock(e)
	return context
}

func receiveFailureKey(in Inbound) writeKey {
	return writeKey{code: in.Code, payload: codec.DedupKey(in.Payload)}
}

func requestedFailureContext(e *ReceiveFailureEvent, context *ReceiveFailureContext) {
	if context != nil {
		e.RequestedContext = context.id
		if context.owner != nil {
			e.RequestedCache = context.owner.id
			e.RequestedRun = context.owner.run
		}
	}
}

// Lookup does not perform recovery. A hit returns its original failure source.
func (c *ReceiveFailureCache) Lookup(context *ReceiveFailureContext, in Inbound, source ReceiveFailureSource) (ReceiveFailureHit, bool) {
	key := receiveFailureKey(in)
	c.mu.Lock()
	e := c.eventLocked("lookup", source)
	requestedFailureContext(&e, context)
	e.Code, e.Payload, e.Active = in.Code, key.payload, c.validLocked(context)
	var result ReceiveFailureHit
	if e.Active {
		if entry, ok := c.entries.Get(key); ok {
			result = ReceiveFailureHit{Class: entry.class, Lookup: ReceiveFailureRef{Run: c.run, Cache: c.id, Sequence: e.Sequence}, Reference: entry.ref, Source: entry.source}
			e.Hit, e.Class, e.Reference, e.Original = true, entry.class, entry.ref, entry.source
		}
	}
	c.publishUnlock(e)
	return result, e.Hit
}

// Record retains only a classified signature or membership failure from the
// current context. The bool is true only for a new entry; concurrent duplicate
// checks preserve the original reference. It never writes accepted caches.
func (c *ReceiveFailureCache) Record(context *ReceiveFailureContext, in Inbound, class ReceiveFailureClass, source ReceiveFailureSource) (ReceiveFailureRef, bool) {
	key := receiveFailureKey(in)
	c.mu.Lock()
	e := c.eventLocked("record", source)
	requestedFailureContext(&e, context)
	e.Code, e.Payload, e.Class, e.Active = in.Code, key.payload, class, c.validLocked(context)
	if e.Active && in.Code >= CodeFirst && in.Code <= CodeLast && (class == ReceiveSignatureFailure || class == ReceiveMembershipFailure) {
		if previous, ok := c.entries.Get(key); ok {
			if previous.class == class {
				e.Reference, e.Original = previous.ref, previous.source
			} else {
				if e.Unavailable == "" {
					e.Unavailable = "conflicting_failure"
				}
			}
		} else {
			e.Reference = ReceiveFailureRef{Run: c.run, Cache: c.id, Sequence: e.Sequence}
			c.entries.Add(key, receiveFailureEntry{class: class, ref: e.Reference, source: source})
			e.Stored = true
		}
	}
	c.publishUnlock(e)
	return e.Reference, e.Stored
}

// Invalidate revokes the cache's publication without closing a borrowed scope.
func (c *ReceiveFailureCache) Invalidate() {
	c.mu.Lock()
	e := c.eventLocked("invalidate", ReceiveFailureSource{})
	c.current, c.entries = nil, nil
	c.publishUnlock(e)
}

func (c *ReceiveFailureCache) Len() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.countLocked()
}

// Close releases all retained failures. A closed cache cannot be reopened.
func (c *ReceiveFailureCache) Close() {
	c.mu.Lock()
	e := c.eventLocked("close", ReceiveFailureSource{})
	c.closed, c.current, c.entries = true, nil, nil
	c.publishUnlock(e)
}
