package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// DupMode selects whether duplicate copies of a message are recorded.
type DupMode uint8

// Duplicate modes.
const (
	DupAll   DupMode = iota // every copy (default)
	DupFirst                // first copy only; not available yet
)

// Options configure a journal. Zero limits mean no limit; DefaultOptions
// returns the defaults of the node configuration.
type Options struct {
	FS  fsys.FS // nil: the operating system
	Dir string
	// KeepHeights keeps the segments that hold heights >= head -
	// KeepHeights.
	KeepHeights uint64
	// MaxBytes caps the total size of the segments.
	MaxBytes     int64
	SegmentBytes int64
	Duplicates   DupMode
	// QueueRecords and QueueBytes bound the queue of the writer goroutine;
	// a record that does not fit is dropped and later reported by a gap
	// record.
	QueueRecords int
	QueueBytes   int64
	// Synchronous writes every record in the caller's goroutine, in Put
	// order, without a queue. The deterministic simulator uses it.
	Synchronous bool
}

// DefaultEnabled is the default of the node setting that turns the journal
// on: a node keeps a journal unless its operator turns it off.
const DefaultEnabled = true

// DefaultOptions returns the defaults: keep 100000 heights and at most 8 GiB
// in segments of 64 MiB, a queue of 65536 records or 64 MiB.
func DefaultOptions(dir string) Options {
	return Options{Dir: dir, KeepHeights: 100000, MaxBytes: 8 << 30, SegmentBytes: 64 << 20, QueueRecords: 65536, QueueBytes: 64 << 20}
}

// ErrUnsupported is returned for an option value that is not available.
var ErrUnsupported = errors.New("journal: option not available")

// Writer receives journal records. Put never blocks.
type Writer interface {
	// Put queues a record. On overflow the record is dropped and a gap
	// record is written when there is room again.
	Put(r Record)
	// Close writes the queued records and closes the journal.
	Close() error
}

// indexSuffix is the suffix of the index file of a closed segment.
const indexSuffix = ".idx"

// SegmentIndex is the index file of a closed segment.
type SegmentIndex struct {
	MinHeight *string          `json:"min_height"` // decimal; null when the segment has no head
	MaxHeight *string          `json:"max_height"`
	FirstWall int64            `json:"first_wall_ns"`
	LastWall  int64            `json:"last_wall_ns"`
	Size      int64            `json:"size"`
	Records   map[string]int64 `json:"records"`
}

// FileWriter writes a journal directory. It is safe for concurrent use.
type FileWriter struct {
	opt Options
	fs  fsys.FS
	id  Identity

	qmu      sync.Mutex // observe.journal.q.mu: queue insertion only
	cond     *sync.Cond
	queue    []Record
	qbytes   int64
	dropped  map[Kind]uint64
	dropMono [2]time.Duration
	closing  bool
	done     chan struct{}

	// Owned by the writing goroutine (or by Put in synchronous mode).
	wmu       sync.Mutex
	log       *wal.Log
	jseq      uint64
	engineRun uint64
	seg       uint64
	stats     segStats
	attached  map[uint32]*PeerRec
	head      *types.Height
	lastSync  time.Time
	err       error
}

type segStats struct {
	minH, maxH  *types.Height
	first, last int64
	counts      map[string]int64
}

// Open opens the journal in opt.Dir for the node identity id. Writing
// starts in a new segment; damaged segments of an earlier run are moved
// aside as package wal does.
func Open(opt Options, id Identity) (*FileWriter, error) {
	if opt.Duplicates != DupAll {
		return nil, ErrUnsupported
	}
	if opt.FS == nil {
		opt.FS = fsys.OS{}
	}
	if opt.SegmentBytes <= 0 {
		opt.SegmentBytes = 64 << 20
	}
	if opt.QueueRecords <= 0 {
		opt.QueueRecords = 65536
	}
	if opt.QueueBytes <= 0 {
		opt.QueueBytes = 64 << 20
	}
	w := &FileWriter{opt: opt, fs: opt.FS, id: id, dropped: map[Kind]uint64{}, attached: map[uint32]*PeerRec{},
		stats: segStats{counts: map[string]int64{}}, done: make(chan struct{})}
	w.cond = sync.NewCond(&w.qmu)
	w.wmu.Lock()
	log, _, err := wal.Open(opt.FS, opt.Dir, wal.Options{SegmentBytes: opt.SegmentBytes, Header: w.segmentHeader})
	if err != nil {
		w.wmu.Unlock()
		return nil, err
	}
	w.log = log
	w.seg = log.Position().Segment
	w.wmu.Unlock()
	if !opt.Synchronous {
		go w.loop()
	} else {
		close(w.done)
	}
	return w, nil
}

// segmentHeader is called by the log for every new segment: it writes the
// index of the segment that was closed and returns the segment record and
// the peer records of the attached peers. It runs with wmu held.
func (w *FileWriter) segmentHeader() []wal.Record {
	if w.log != nil {
		w.writeIndex(w.seg)
		w.seg++
	}
	// The head in force when the segment starts covers its first records.
	w.stats = segStats{counts: map[string]int64{}, minH: w.head, maxH: w.head}
	var out []wal.Record
	add := func(r Record) {
		k, _ := kindOf(r.Body)
		w.jseq++
		b, err := encodeBody(r, w.jseq)
		if err != nil {
			w.err = err
			return
		}
		w.stats.counts[k.String()]++
		out = append(out, wal.Record{Format: Format, Kind: uint8(k), Body: b})
	}
	add(Record{Body: &SegmentRec{Identity: w.id, EngineRun: w.engineRun}})
	idx := make([]uint32, 0, len(w.attached))
	for i := range w.attached { //wbft:unordered the indices are sorted below
		idx = append(idx, i)
	}
	slices.Sort(idx)
	for _, i := range idx {
		add(Record{Body: w.attached[i]})
	}
	return out
}

func (w *FileWriter) writeIndex(seg uint64) {
	ix := SegmentIndex{FirstWall: w.stats.first, LastWall: w.stats.last, Records: w.stats.counts}
	if w.stats.minH != nil {
		a, b := w.stats.minH.String(), w.stats.maxH.String()
		ix.MinHeight, ix.MaxHeight = &a, &b
	}
	name := filepath.Join(w.opt.Dir, fmt.Sprintf("%020d.wal", seg))
	if n, err := w.fs.Size(name); err == nil {
		ix.Size = n
	}
	b, err := json.Marshal(ix)
	if err != nil {
		return
	}
	_ = fsys.WriteFileAtomic(w.fs, w.opt.Dir, name+indexSuffix, b, 0o600)
}

// SetEngineRun sets the engine run number written in later segment
// records.
func (w *FileWriter) SetEngineRun(n uint64) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	w.engineRun = n
}

// Put implements Writer.
func (w *FileWriter) Put(r Record) {
	if w.opt.Synchronous {
		w.wmu.Lock()
		w.write(r)
		w.wmu.Unlock()
		return
	}
	w.qmu.Lock()
	defer w.qmu.Unlock()
	if w.closing {
		return
	}
	n := size(r)
	if _, ok := r.Body.(headNote); ok {
		if len(w.queue) < w.opt.QueueRecords {
			w.queue = append(w.queue, r)
			w.cond.Signal()
		}
		return
	}
	if len(w.queue) >= w.opt.QueueRecords || w.qbytes+n > w.opt.QueueBytes {
		k, _ := kindOf(r.Body)
		if len(w.dropped) == 0 {
			w.dropMono[0] = monoOf(r)
		}
		w.dropMono[1] = monoOf(r)
		w.dropped[k]++
		return
	}
	w.queue = append(w.queue, r)
	w.qbytes += n
	w.cond.Signal()
}

func monoOf(r Record) time.Duration {
	switch b := r.Body.(type) {
	case *MsgRec:
		return b.Mono
	case *StepRec:
		return b.Mono
	}
	return 0
}

// NoteHead tells the journal the node's head: it is recorded in the segment
// index and triggers pruning.
func (w *FileWriter) NoteHead(h types.Height) {
	w.Put(Record{Kind: 0, Body: headNote{h}})
}

// headNote is an internal queue entry.
type headNote struct{ h types.Height }

func (w *FileWriter) loop() {
	defer close(w.done)
	for {
		w.qmu.Lock()
		for len(w.queue) == 0 && len(w.dropped) == 0 && !w.closing {
			w.cond.Wait()
		}
		batch := w.queue
		w.queue, w.qbytes = nil, 0
		var gap *GapRec
		if len(w.dropped) > 0 {
			gap = &GapRec{FirstMono: w.dropMono[0], LastMono: w.dropMono[1]}
			ks := make([]Kind, 0, len(w.dropped))
			for k := range w.dropped { //wbft:unordered the kinds are sorted below
				ks = append(ks, k)
			}
			slices.Sort(ks)
			for _, k := range ks {
				gap.Dropped += w.dropped[k]
				gap.ByKind = append(gap.ByKind, KindCount{Kind: uint64(k), Count: w.dropped[k]})
			}
			w.dropped = map[Kind]uint64{}
		}
		closing := w.closing
		w.qmu.Unlock()
		w.wmu.Lock()
		for _, r := range batch {
			w.write(r)
		}
		if gap != nil {
			w.write(Record{Body: gap})
		}
		// Records are synced once a second and when a segment rotates.
		if now := time.Now(); now.Sub(w.lastSync) >= time.Second {
			w.lastSync = now
			if err := w.log.Sync(); err != nil && w.err == nil {
				w.err = err
			}
		}
		w.wmu.Unlock()
		if closing {
			w.qmu.Lock()
			empty := len(w.queue) == 0 && len(w.dropped) == 0
			w.qmu.Unlock()
			if empty {
				return
			}
		}
	}
}

// write writes one record; wmu is held.
func (w *FileWriter) write(r Record) {
	if hn, ok := r.Body.(headNote); ok {
		h := hn.h
		w.head = &h
		if w.stats.minH == nil || h.Cmp(*w.stats.minH) < 0 {
			w.stats.minH = &h
		}
		if w.stats.maxH == nil || h.Cmp(*w.stats.maxH) > 0 {
			w.stats.maxH = &h
		}
		w.prune()
		return
	}
	k, ok := kindOf(r.Body)
	if !ok || w.err != nil {
		return
	}
	switch b := r.Body.(type) {
	case *PeerRec:
		if b.Event == "attached" {
			c := *b
			w.attached[b.PeerIdx] = &c
		} else {
			delete(w.attached, b.PeerIdx)
		}
	case *StepRec:
		if w.stats.first == 0 {
			w.stats.first = b.WallNs
		}
		w.stats.last = b.WallNs
	case *MsgRec:
		if w.stats.first == 0 {
			w.stats.first = b.WallNs
		}
		w.stats.last = b.WallNs
	}
	body, err := encodeBody(r, w.jseq+1)
	if err != nil {
		w.err = err
		return
	}
	if w.log.WouldRotate(wal.Record{Body: body}) {
		// The header records of the new segment take the next numbers.
		if err := w.log.Rotate(); err != nil {
			w.err = err
			return
		}
		if body, err = encodeBody(r, w.jseq+1); err != nil {
			w.err = err
			return
		}
	}
	if _, err := w.log.Append(wal.Record{Format: Format, Kind: uint8(k), Body: body}); err != nil {
		w.err = err
		return
	}
	w.jseq++
	w.stats.counts[k.String()]++
}

// Err returns the first write error; writing stops after it.
func (w *FileWriter) Err() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.err
}

// Sync makes the written records durable.
func (w *FileWriter) Sync() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.log.Sync()
}

// Close implements Writer.
func (w *FileWriter) Close() error {
	if !w.opt.Synchronous {
		w.qmu.Lock()
		w.closing = true
		w.cond.Signal()
		w.qmu.Unlock()
	}
	<-w.done
	w.wmu.Lock()
	defer w.wmu.Unlock()
	err := w.log.Close()
	w.writeIndex(w.seg)
	if w.err != nil {
		return w.err
	}
	return err
}

// prune removes old segments by the retention rules; wmu is held.
func (w *FileWriter) prune() {
	if w.head == nil {
		return
	}
	_, _ = Prune(w.fs, w.opt.Dir, *w.head, w.opt, w.seg)
}

// PruneResult reports what Prune removed.
type PruneResult struct {
	Removed []string
	Bytes   int64 // bytes of the remaining segments
}

// Prune removes closed segments of the journal in dir: first those whose
// highest head is below head - KeepHeights, then the oldest ones while the
// total size is above MaxBytes. Segment current and later ones are never
// removed; segments without an index file are removed only by size.
func Prune(fs fsys.FS, dir string, head types.Height, opt Options, current uint64) (PruneResult, error) {
	var res PruneResult
	segs, err := wal.Segments(fs, dir)
	if err != nil {
		return res, err
	}
	var floor *types.Height
	if opt.KeepHeights > 0 {
		if f, ok := head.Sub(types.HeightFromUint64(opt.KeepHeights)); ok {
			floor = &f
		}
	}
	var total int64
	for _, s := range segs {
		total += s.Size
	}
	remove := func(s wal.SegmentInfo) error {
		if err := wal.RemoveSegment(fs, dir, s.Index); err != nil {
			return err
		}
		_ = fs.Remove(filepath.Join(dir, s.Name+indexSuffix))
		res.Removed = append(res.Removed, s.Name)
		total -= s.Size
		return nil
	}
	var kept []wal.SegmentInfo
	for _, s := range segs {
		if s.Index >= current {
			kept = append(kept, s)
			continue
		}
		if floor != nil {
			if ix, ok := readIndex(fs, dir, s.Name); ok && ix.MaxHeight != nil {
				mh, ok := new(big.Int).SetString(*ix.MaxHeight, 10)
				if ok {
					if h, err := types.HeightFromBig(mh); err == nil && h.Cmp(*floor) < 0 {
						if err := remove(s); err != nil {
							return res, err
						}
						continue
					}
				}
			}
		}
		kept = append(kept, s)
	}
	if opt.MaxBytes > 0 {
		for _, s := range kept {
			if total <= opt.MaxBytes || s.Index >= current {
				break
			}
			if err := remove(s); err != nil {
				return res, err
			}
		}
	}
	res.Bytes = total
	return res, nil
}

func readIndex(fs fsys.FS, dir, name string) (SegmentIndex, bool) {
	b, err := fs.ReadFile(filepath.Join(dir, name+indexSuffix))
	if err != nil {
		return SegmentIndex{}, false
	}
	var ix SegmentIndex
	if json.Unmarshal(b, &ix) != nil {
		return SegmentIndex{}, false
	}
	return ix, true
}

// Reader reads the records of a journal directory in order.
type Reader struct {
	r *wal.Reader
}

// OpenReader returns a reader of the journal in dir, from its first
// segment. A segment being written is read up to its last complete record.
func OpenReader(fs fsys.FS, dir string) (*Reader, error) {
	if fs == nil {
		fs = fsys.OS{}
	}
	r, err := wal.OpenReader(fs, dir, wal.Position{})
	if err != nil {
		return nil, err
	}
	return &Reader{r: r}, nil
}

// Next returns the next record, or io.EOF after the last one.
func (r *Reader) Next() (Record, error) {
	rec, _, err := r.r.Next()
	if err != nil {
		return Record{}, err
	}
	if rec.Format != Format {
		return Record{}, fmt.Errorf("%w: frame format %d", ErrRecord, rec.Format)
	}
	return decodeBody(Kind(rec.Kind), rec.Body)
}

// ReadAll returns every record of the journal in dir.
func ReadAll(fs fsys.FS, dir string) ([]Record, error) {
	r, err := OpenReader(fs, dir)
	if err != nil {
		return nil, err
	}
	var out []Record
	for {
		rec, err := r.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, rec)
	}
}

// IsJournalFile reports whether name is a segment or index file of a
// journal directory.
func IsJournalFile(name string) bool {
	return strings.HasSuffix(name, ".wal") || strings.HasSuffix(name, ".wal"+indexSuffix)
}
