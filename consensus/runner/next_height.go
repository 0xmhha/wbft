package runner

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// NextHeightLimits enables a separate receive lane for exactly the next
// sequence. All limits are explicit and positive; nil Config.NextHeight keeps
// the original receive path. Bytes counts owned raw payloads throughout their
// lifetime, including queued, checking and core-dispatch work. It is not a
// process heap, CPU or WAL disk bound. One additional receive worker performs
// outer authentication, independently of the current-height workers.
type NextHeightLimits struct {
	Entries   uint64 `json:"entries,string"`
	Bytes     uint64 `json:"bytes,string"`
	PerPeer   uint64 `json:"per_peer,string"`
	PerSource uint64 `json:"per_source,string"`
}

const (
	nextHeightFormat uint8 = 2
	walDeferredAdmit uint8 = 7
	walDeferredInput uint8 = 8
	walDeferredDrop  uint8 = 9
)

var errNextHeightWAL = errors.New("runner: next-height WAL requires NextHeight configuration")

func sameDeferred(a, b deferredRecord) bool {
	return a.ID == b.ID && a.Code == b.Code && bytes.Equal(a.Payload, b.Payload) && a.Peer == b.Peer && a.RecvMono == b.RecvMono && a.CaptureRun == b.CaptureRun && a.Capture == b.Capture
}

type deferredStage uint8

const (
	deferredQueued deferredStage = iota
	deferredChecking
	deferredChecked
	deferredPending
	deferredDispatch
	deferredPersisting
	deferredRetired
)

// deferredRecord preserves the first physical reference as metadata. It never
// substitutes a capture in the current journal run for a capture in an older
// run. Missing journal bytes do not change functional admission or replay.
type deferredRecord struct {
	stream     *transport.WriteSession // runtime-only; no stream authority is restored from WAL
	ID         uint64
	Code       uint64
	Payload    []byte
	Peer       types.Address
	RecvMono   uint64
	CaptureRun string
	Capture    uint64
}

func (d deferredRecord) message() consensus.Message {
	return consensus.Message{Code: codec.Code(d.Code), Payload: d.Payload, Peer: d.Peer, RecvMono: time.Duration(d.RecvMono)}
}

type deferredEntry struct {
	record deferredRecord
	outer  *consensus.OuterSigner
	stage  deferredStage
}

// nextHeightPool retains each reservation until core consumption returns.
// Worker completion checks pointer ownership, so work from a stopped run
// cannot publish into the next run even when a restored ID is the same.
type nextHeightPool struct {
	mu      sync.Mutex // runner.nextheight.mu
	cond    *sync.Cond
	limits  NextHeightLimits
	active  bool
	next    uint64
	bytes   uint64
	entries map[uint64]*deferredEntry
	order   []uint64
}

func newNextHeightPool(l NextHeightLimits) *nextHeightPool {
	p := &nextHeightPool{limits: l, entries: map[uint64]*deferredEntry{}}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *nextHeightPool) removeLocked(e *deferredEntry) {
	if p.entries[e.record.ID] != e {
		return
	}
	delete(p.entries, e.record.ID)
	p.bytes -= uint64(len(e.record.Payload))
	p.order = slices.DeleteFunc(p.order, func(id uint64) bool { return id == e.record.ID })
}

func (p *nextHeightPool) offer(in transport.Inbound, run string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || uint64(len(p.entries)) >= p.limits.Entries || uint64(len(in.Payload)) > p.limits.Bytes-p.bytes || p.next == ^uint64(0) {
		return false
	}
	var peers uint64
	for _, id := range p.order {
		if p.entries[id].record.Peer == in.Peer {
			peers++
		}
	}
	if peers >= p.limits.PerPeer {
		return false
	}
	p.next++
	d := deferredRecord{ID: p.next, Code: in.Code, Payload: bytes.Clone(in.Payload), Peer: in.Peer, RecvMono: uint64(in.RecvMono), CaptureRun: run, Capture: in.Capture, stream: in.Stream}
	if run == "" || in.Capture == 0 {
		d.CaptureRun, d.Capture = "", 0
	}
	p.entries[d.ID] = &deferredEntry{record: d}
	p.order = append(p.order, d.ID)
	p.bytes += uint64(len(d.Payload))
	p.cond.Signal()
	return true
}

func (p *nextHeightPool) queuedLocked() *deferredEntry {
	if !p.active {
		return nil
	}
	for _, id := range p.order {
		if e := p.entries[id]; e.stage == deferredQueued {
			return e
		}
	}
	return nil
}

// checkNextHeight authenticates only the outer signer. Nothing in this lane
// enters the verified cache, validator evidence, observation or quorum paths.
func (r *Runner) checkNextHeight() bool {
	p := r.nextHeight
	if p == nil {
		return false
	}
	p.mu.Lock()
	e := p.queuedLocked()
	if e == nil {
		p.mu.Unlock()
		return false
	}
	e.stage = deferredChecking
	p.mu.Unlock()
	o, err := consensus.RecoverOuter(codec.Code(e.record.Code), e.record.Payload)
	if err == nil {
		snap := r.snap.Load()
		if snap != nil && snap.Running && outsideWindow(snap, o.Code, o.View) {
			err = errors.New("runner: deferred view outside receive window")
		}
	}
	p.mu.Lock()
	if p.entries[e.record.ID] == e && e.stage == deferredRetired {
		p.removeLocked(e)
	} else if p.entries[e.record.ID] == e {
		var sources uint64
		if err == nil {
			for _, id := range p.order {
				other := p.entries[id]
				if other != e && other.outer != nil && other.outer.Source == o.Source {
					sources++
					if other.outer.Code == o.Code && other.outer.View.Cmp(o.View) == 0 {
						err = errors.New("runner: deferred slot already occupied")
					}
				}
			}
		}
		if err != nil || sources >= p.limits.PerSource {
			p.removeLocked(e)
		} else {
			e.outer, e.stage = o, deferredChecked
		}
	}
	p.mu.Unlock()
	r.wake()
	return true
}

func (r *Runner) nextHeightWorker() {
	defer r.loopDone.Done()
	p := r.nextHeight
	for {
		p.mu.Lock()
		for p.queuedLocked() == nil {
			select {
			case <-r.stopLoop:
				p.mu.Unlock()
				return
			default:
			}
			p.cond.Wait()
		}
		p.mu.Unlock()
		r.checkNextHeight()
	}
}

func (r *Runner) writeDeferred(kind uint8, d deferredRecord) error {
	body, err := rlp.Encode(&d)
	if err == nil {
		_, err = r.d.WAL.AppendSync(wal.Record{Format: nextHeightFormat, Kind: kind, Body: body})
	}
	return err
}

// settleNextHeight is run only by the core actor. A future admission is durable
// before becoming pending. Expiry is durable before its reservation is freed.
func (r *Runner) settleNextHeight() bool {
	p := r.nextHeight
	if p == nil {
		return false
	}
	p.mu.Lock()
	current := r.core.Snapshot().View.Sequence
	for _, id := range p.order {
		e := p.entries[id]
		if e.stage != deferredChecked && e.stage != deferredPending {
			continue
		}
		expired := e.outer.View.Sequence.Cmp(current) < 0 || e.outer.View.Sequence.Cmp(current.AddUint64(1)) > 0
		if expired && e.stage == deferredChecked {
			p.removeLocked(e)
			p.mu.Unlock()
			return true
		}
		if !expired && e.stage == deferredPending {
			continue
		}
		kind := walDeferredAdmit
		if expired {
			kind = walDeferredDrop
		}
		e.stage = deferredPersisting
		p.mu.Unlock()
		// Receiver.Offer never waits for this fsync while holding its queue lock.
		err := r.writeDeferred(kind, e.record)
		p.mu.Lock()
		if expired {
			p.removeLocked(e)
		} else {
			e.stage = deferredPending
		}
		p.mu.Unlock()
		if err != nil {
			r.halt(err)
			return false
		}
		return true
	}
	p.mu.Unlock()
	return false
}

func (r *Runner) takeNextHeight() (queued, bool) {
	p := r.nextHeight
	if p == nil {
		return queued{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := r.core.Snapshot().View.Sequence
	for _, id := range p.order {
		e := p.entries[id]
		if e.stage == deferredPending && e.outer.View.Sequence.Cmp(current) == 0 {
			e.stage = deferredDispatch
			// Keep the original bytes and re-enter onMessage, which checks the
			// current validator set for every outer and attached signature.
			// A capture in an older writer run must not become a current-run
			// CapturedMessage; journalStep therefore keeps this input inline.
			return queued{in: e.record.message(), via: viaPeer, deferred: e}, true
		}
	}
	return queued{}, false
}

func (p *nextHeightPool) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = false
	// A worker may still be finishing an outer recovery. Keep that raw
	// reservation until it returns; it cannot publish into the next run.
	for _, id := range slices.Clone(p.order) {
		e := p.entries[id]
		if e.stage == deferredChecking || e.stage == deferredRetired {
			e.stage = deferredRetired
		} else {
			p.removeLocked(e)
		}
	}
}

// NextHeightUsage reports reserved raw payload entries and bytes in all stages.
func (r *Runner) NextHeightUsage() (uint64, uint64) {
	if r.nextHeight == nil {
		return 0, 0
	}
	p := r.nextHeight
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint64(len(p.entries)), p.bytes
}

type deferredBoundary struct {
	Boundary []byte
	Limits   NextHeightLimits
	Pending  []deferredRecord
}

func (r *Runner) encodeRunnerBoundary(kind uint8, b boundaryRec) (wal.Record, error) {
	rec, err := r.encodeBaseBoundary(kind, b)
	if err != nil || !r.cfg.Core.Improvements.Has(consensus.BindPriorHead) {
		return rec, err
	}
	return encodePriorBoundary(rec, b.PriorSource, b.Head)
}

func (r *Runner) encodeBaseBoundary(kind uint8, b boundaryRec) (wal.Record, error) {
	rec, err := encodeBoundary(kind, b)
	if err != nil || r.nextHeight == nil {
		return rec, err
	}
	p := r.nextHeight
	p.mu.Lock()
	w := deferredBoundary{Boundary: rec.Body, Limits: p.limits, Pending: []deferredRecord{}}
	for _, id := range p.order {
		e := p.entries[id]
		if e.stage == deferredPending || e.stage == deferredDispatch {
			w.Pending = append(w.Pending, e.record)
		}
	}
	p.mu.Unlock()
	rec.Format = nextHeightFormat
	rec.Body, err = rlp.Encode(&w)
	return rec, err
}

func decodeRunnerBoundary(rec wal.Record) (boundaryRec, *deferredBoundary, error) {
	if rec.Format == priorHeadFormat {
		base, source, err := decodePriorBoundary(rec)
		if err != nil {
			return boundaryRec{}, nil, err
		}
		b, pending, err := decodeRunnerBoundary(base)
		b.PriorSource = source
		return b, pending, err
	}

	if rec.Format == walFormat {
		b, err := decodeBoundary(rec.Body)
		return b, nil, err
	}
	if rec.Format != nextHeightFormat {
		return boundaryRec{}, nil, fmt.Errorf("runner: unsupported boundary format %d", rec.Format)
	}
	var w deferredBoundary
	if err := rlp.DecodeStrict(rec.Body, &w); err != nil {
		return boundaryRec{}, nil, err
	}
	b, err := decodeBoundary(w.Boundary)
	return b, &w, err
}

func deferredInput(d deferredRecord) (inputRec, error) {
	b, err := inputlog.Encode(d.message())
	return inputRec{Kind: inputlog.KindMessage, Body: b}, err
}

// pendingFromWAL restores the receive lane independently of the core replay
// height. The application may have synchronised while the engine was stopped,
// so its new height need not have a matching core boundary yet.
func (r *Runner) pendingFromWAL(records []wal.Record) ([]deferredRecord, error) {
	start := -1
	var checkpoint deferredBoundary
	for i, rec := range records {
		if (rec.Format != nextHeightFormat && rec.Format != priorHeadFormat) || (rec.Kind != walRunStart && rec.Kind != walEndHeight) {
			continue
		}
		_, cp, err := decodeRunnerBoundary(rec)
		if err != nil {
			return nil, err
		}
		if cp == nil {
			continue
		}
		if r.nextHeight == nil || cp.Limits != r.nextHeight.limits {
			return nil, errNextHeightWAL
		}
		start, checkpoint = i, *cp
	}
	pending := map[uint64]deferredRecord{}
	for _, d := range checkpoint.Pending {
		if _, exists := pending[d.ID]; exists {
			return nil, errors.New("runner: duplicate deferred checkpoint ID")
		}
		pending[d.ID] = d
	}
	for _, rec := range records[start+1:] {
		if rec.Format != nextHeightFormat {
			continue
		}
		if rec.Kind != walDeferredAdmit && rec.Kind != walDeferredInput && rec.Kind != walDeferredDrop {
			continue
		}
		var d deferredRecord
		if err := rlp.DecodeStrict(rec.Body, &d); err != nil {
			return nil, err
		}
		old, exists := pending[d.ID]
		if rec.Kind == walDeferredAdmit {
			if exists {
				return nil, errors.New("runner: duplicate deferred admission")
			}
			pending[d.ID] = d
		} else {
			if !exists || !sameDeferred(old, d) {
				return nil, errors.New("runner: deferred completion has no matching admission")
			}
			delete(pending, d.ID)
		}
	}
	var out []deferredRecord
	for _, d := range pending { //wbft:unordered sorted by admission ID below
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b deferredRecord) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out, nil
}

// restoreNextHeight rebuilds quotas from the latest checkpoint and subsequent
// ordered admissions/releases. It does not trust persisted signer addresses.
func (r *Runner) restoreNextHeight(pending []deferredRecord) error {
	p := r.nextHeight
	if p == nil {
		if len(pending) != 0 {
			return errors.New("runner: next-height WAL requires NextHeight configuration")
		}
		return nil
	}
	p.clear()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, d := range pending {
		if d.ID == 0 || p.entries[d.ID] != nil || uint64(len(p.entries)) >= p.limits.Entries || uint64(len(d.Payload)) > p.limits.Bytes-p.bytes {
			return errors.New("runner: deferred checkpoint exceeds limits or repeats an ID")
		}
		o, err := consensus.RecoverOuter(codec.Code(d.Code), d.Payload)
		if err != nil {
			return fmt.Errorf("runner: deferred checkpoint envelope: %w", err)
		}
		var peers, sources uint64
		for _, id := range p.order {
			e := p.entries[id]
			if e.record.Peer == d.Peer {
				peers++
			}
			if e.outer != nil && e.outer.Source == o.Source {
				sources++
				if e.outer.Code == o.Code && e.outer.View.Cmp(o.View) == 0 {
					return errors.New("runner: deferred checkpoint repeats a slot")
				}
			}
		}
		if peers >= p.limits.PerPeer || sources >= p.limits.PerSource {
			return errors.New("runner: deferred checkpoint exceeds peer or source limit")
		}
		p.entries[d.ID] = &deferredEntry{record: d, outer: o, stage: deferredPending}
		p.order = append(p.order, d.ID)
		p.bytes += uint64(len(d.Payload))
		p.next = max(p.next, d.ID)
	}
	return nil
}
