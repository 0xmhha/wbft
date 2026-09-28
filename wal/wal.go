package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/0xmhha/wbft/internal/fsys"
)

// Record is one log record: a format number, a kind and an opaque body. The
// log does not interpret them.
type Record struct {
	Format uint8
	Kind   uint8
	Body   []byte
}

// Frame layout: length (4 bytes, big endian) of the bytes after the
// checksum, CRC32C (4 bytes, big endian) of those bytes, then format (1),
// kind (1) and the body.
const (
	headerLen = 8
	// MaxRecordBytes bounds the body of one record; a larger length in a
	// frame is damage.
	MaxRecordBytes = 1 << 30
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Errors.
var (
	// ErrCorrupt reports a frame whose checksum or length is wrong, or an
	// incomplete frame that is not at the end of the log.
	ErrCorrupt = errors.New("wal: corrupt record")
	// ErrClosed is returned by a closed log.
	ErrClosed = errors.New("wal: log closed")
	// ErrTooLarge is returned for a record body above MaxRecordBytes.
	ErrTooLarge = errors.New("wal: record too large")
)

// Suffixes of the file names in a log directory.
const (
	segmentSuffix   = ".wal"
	corruptedSuffix = ".corrupted"
)

// DefaultSegmentBytes is the default segment size.
const DefaultSegmentBytes = 64 << 20

// Options configure a log.
type Options struct {
	// SegmentBytes starts a new segment once the current one would grow
	// beyond it. Zero means DefaultSegmentBytes.
	SegmentBytes int64
	// KeepHeights is the number of heights whose segments the owner keeps;
	// the log only stores it for its owner (default 2). The message journal
	// has retention rules of its own and leaves it at zero.
	KeepHeights int
	// Header returns the records written at the start of every new segment
	// before any other record, so that a segment can be read on its own.
	Header func() []Record
}

// Position is the place of a record: the segment index and the byte offset
// of its frame in the segment.
type Position struct {
	Segment uint64
	Offset  int64
}

// Recovery reports what Open found in the directory.
type Recovery struct {
	Segments  int      // segments found
	Records   int      // readable records in them
	TornBytes int64    // bytes of an incomplete last frame that were cut off
	Corrupted []string // segments moved aside, in order
}

// Writer appends records.
type Writer interface {
	// Append adds a record to the write buffer.
	Append(r Record) (Position, error)
	// AppendSync adds a record and makes it and every record before it
	// durable before it returns.
	AppendSync(r Record) (Position, error)
	// Close syncs and closes the log.
	Close() error
}

// Log is an append-only log in a directory of numbered segment files. It is
// safe for concurrent use.
type Log struct {
	mu      sync.Mutex // wal.writer.mu
	fs      fsys.FS
	dir     string
	opt     Options
	seg     uint64
	f       fsys.File
	size    int64 // bytes written to the current segment file
	buf     []byte
	err     error // sticky write error
	closed  bool
	started bool
}

var _ Writer = (*Log)(nil)

func segmentName(i uint64) string { return fmt.Sprintf("%020d%s", i, segmentSuffix) }

// segmentIndex parses a segment file name.
func segmentIndex(name string) (uint64, bool) {
	s, ok := strings.CutSuffix(name, segmentSuffix)
	if !ok || len(s) != 20 {
		return 0, false
	}
	i, err := strconv.ParseUint(s, 10, 64)
	return i, err == nil
}

// SegmentInfo describes one segment file.
type SegmentInfo struct {
	Index uint64
	Name  string // file name in the directory
	Size  int64
}

// Segments lists the segment files of dir in index order; moved-aside
// segments are not listed.
func Segments(fs fsys.FS, dir string) ([]SegmentInfo, error) {
	names, err := fs.ReadDir(dir)
	if err != nil {
		if fsys.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SegmentInfo
	for _, n := range names {
		i, ok := segmentIndex(n)
		if !ok {
			continue
		}
		size, err := fs.Size(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, SegmentInfo{Index: i, Name: n, Size: size})
	}
	return out, nil
}

// Encode returns the frame of r.
func Encode(r Record) ([]byte, error) {
	if len(r.Body) > MaxRecordBytes {
		return nil, ErrTooLarge
	}
	out := make([]byte, headerLen+2+len(r.Body))
	binary.BigEndian.PutUint32(out[0:4], uint32(2+len(r.Body)))
	out[8], out[9] = r.Format, r.Kind
	copy(out[10:], r.Body)
	binary.BigEndian.PutUint32(out[4:8], crc32.Checksum(out[8:], castagnoli))
	return out, nil
}

// scanResult is the outcome of reading one segment.
type scanResult struct {
	records []Record
	ends    []int64 // end offset of each record
	good    int64   // end of the last complete, valid frame
	torn    bool    // an incomplete frame follows good
	corrupt bool    // a damaged frame follows good
}

// decodeFrame reads one frame from b. n is the frame length; torn reports an
// incomplete frame, corrupt a damaged one.
func decodeFrame(b []byte) (r Record, n int, torn, corrupt bool) {
	if len(b) < headerLen {
		return Record{}, 0, true, false
	}
	l := binary.BigEndian.Uint32(b[0:4])
	if l < 2 || l > MaxRecordBytes+2 {
		return Record{}, 0, false, true
	}
	if int64(len(b)) < headerLen+int64(l) {
		return Record{}, 0, true, false
	}
	payload := b[headerLen : headerLen+int(l)]
	if crc32.Checksum(payload, castagnoli) != binary.BigEndian.Uint32(b[4:8]) {
		return Record{}, 0, false, true
	}
	return Record{Format: payload[0], Kind: payload[1], Body: append([]byte(nil), payload[2:]...)}, headerLen + int(l), false, false
}

func scan(b []byte) scanResult {
	var res scanResult
	for off := 0; off < len(b); {
		r, n, torn, corrupt := decodeFrame(b[off:])
		if torn {
			res.torn = true
			return res
		}
		if corrupt {
			res.corrupt = true
			return res
		}
		off += n
		res.records = append(res.records, r)
		res.ends = append(res.ends, int64(off))
		res.good = int64(off)
	}
	return res
}

// Open opens the log in dir, creating the directory if needed, and repairs
// it: an incomplete frame at the end of the last segment is cut off; a
// segment with a damaged frame (or an incomplete one before the last
// segment) is renamed with the suffix ".corrupted", together with every
// later segment, so that a reader never continues past damage. Writing
// starts in a new segment.
func Open(fs fsys.FS, dir string, opt Options) (*Log, Recovery, error) {
	if opt.SegmentBytes <= 0 {
		opt.SegmentBytes = DefaultSegmentBytes
	}
	if opt.KeepHeights <= 0 {
		opt.KeepHeights = 2
	}
	var rec Recovery
	if err := fs.MkdirAll(dir, 0o700); err != nil {
		return nil, rec, err
	}
	segs, err := Segments(fs, dir)
	if err != nil {
		return nil, rec, err
	}
	rec.Segments = len(segs)
	next := uint64(0)
	damaged := false
	for i, s := range segs {
		next = s.Index + 1
		p := filepath.Join(dir, s.Name)
		if damaged {
			if err := fs.Rename(p, p+corruptedSuffix); err != nil {
				return nil, rec, err
			}
			rec.Corrupted = append(rec.Corrupted, s.Name)
			continue
		}
		b, err := fs.ReadFile(p)
		if err != nil {
			return nil, rec, err
		}
		res := scan(b)
		rec.Records += len(res.records)
		last := i == len(segs)-1
		switch {
		case res.corrupt || (res.torn && !last):
			damaged = true
			if err := fs.Rename(p, p+corruptedSuffix); err != nil {
				return nil, rec, err
			}
			rec.Corrupted = append(rec.Corrupted, s.Name)
		case res.torn:
			f, err := fs.OpenFile(p, os.O_RDWR, 0o600)
			if err != nil {
				return nil, rec, err
			}
			rec.TornBytes = int64(len(b)) - res.good
			err = f.Truncate(res.good)
			if err == nil {
				err = f.Sync()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return nil, rec, err
			}
		}
	}
	if err := fs.SyncDir(dir); err != nil {
		return nil, rec, err
	}
	l := &Log{fs: fs, dir: dir, opt: opt, seg: next}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.startSegment(next); err != nil {
		return nil, rec, err
	}
	return l, rec, nil
}

// startSegment creates segment i, makes its name durable and writes the
// header records into the buffer.
func (l *Log) startSegment(i uint64) error {
	f, err := l.fs.OpenFile(filepath.Join(l.dir, segmentName(i)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := l.fs.SyncDir(l.dir); err != nil {
		f.Close()
		return err
	}
	l.f, l.seg, l.size, l.started = f, i, 0, true
	if l.opt.Header != nil {
		for _, r := range l.opt.Header() {
			b, err := Encode(r)
			if err != nil {
				return err
			}
			l.buf = append(l.buf, b...)
		}
	}
	return nil
}

// flush writes the buffer to the current segment.
func (l *Log) flush() error {
	if len(l.buf) == 0 {
		return nil
	}
	n, err := l.f.Write(l.buf)
	l.size += int64(n)
	l.buf = l.buf[:0]
	return err
}

// rotate syncs and closes the current segment and starts the next one.
func (l *Log) rotate() error {
	if err := l.flush(); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	if err := l.f.Close(); err != nil {
		return err
	}
	return l.startSegment(l.seg + 1)
}

func (l *Log) add(r Record) (Position, error) {
	if l.closed {
		return Position{}, ErrClosed
	}
	if l.err != nil {
		return Position{}, l.err
	}
	b, err := Encode(r)
	if err != nil {
		return Position{}, err
	}
	pending := l.size + int64(len(l.buf))
	if pending > 0 && pending+int64(len(b)) > l.opt.SegmentBytes {
		if err := l.rotate(); err != nil {
			l.err = err
			return Position{}, err
		}
	}
	pos := Position{Segment: l.seg, Offset: l.size + int64(len(l.buf))}
	l.buf = append(l.buf, b...)
	return pos, nil
}

// Append implements Writer.
func (l *Log) Append(r Record) (Position, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.add(r)
}

// AppendSync implements Writer.
func (l *Log) AppendSync(r Record) (Position, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	pos, err := l.add(r)
	if err != nil {
		return pos, err
	}
	return pos, l.syncLocked()
}

func (l *Log) syncLocked() error {
	if err := l.flush(); err != nil {
		l.err = err
		return err
	}
	if err := l.f.Sync(); err != nil {
		l.err = err
		return err
	}
	return nil
}

// Flush writes the buffered records to the segment file without syncing it.
func (l *Log) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.err != nil {
		return l.err
	}
	if err := l.flush(); err != nil {
		l.err = err
		return err
	}
	return nil
}

// Sync makes every appended record durable.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.err != nil {
		return l.err
	}
	return l.syncLocked()
}

// Close implements Writer.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	err := l.err
	if err == nil {
		err = l.syncLocked()
	}
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Position returns the position the next record will get.
func (l *Log) Position() Position {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Position{Segment: l.seg, Offset: l.size + int64(len(l.buf))}
}

// Options returns the options of the log.
func (l *Log) Options() Options { return l.opt }

// FS returns the file system and the directory of the log.
func (l *Log) FS() (fsys.FS, string) { return l.fs, l.dir }

// RemoveBefore deletes the segments with an index below seg, except the
// segment being written.
func (l *Log) RemoveBefore(seg uint64) error {
	l.mu.Lock()
	cur := l.seg
	l.mu.Unlock()
	segs, err := Segments(l.fs, l.dir)
	if err != nil {
		return err
	}
	removed := false
	for _, s := range segs {
		if s.Index >= seg || s.Index >= cur {
			break
		}
		if err := l.fs.Remove(filepath.Join(l.dir, s.Name)); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return l.fs.SyncDir(l.dir)
	}
	return nil
}

// RemoveSegment deletes one closed segment of the log in dir.
func RemoveSegment(fs fsys.FS, dir string, index uint64) error {
	if err := fs.Remove(filepath.Join(dir, segmentName(index))); err != nil {
		return err
	}
	return fs.SyncDir(dir)
}

// Reader reads the records of a log directory in order.
type Reader struct {
	fs   fsys.FS
	dir  string
	segs []SegmentInfo
	i    int
	data []byte
	off  int64
	err  error
}

// OpenReader returns a reader that starts at from and continues through the
// later segments. Moved-aside segments are skipped. It reads a segment
// that is being written up to its last complete record.
func OpenReader(fs fsys.FS, dir string, from Position) (*Reader, error) {
	segs, err := Segments(fs, dir)
	if err != nil {
		return nil, err
	}
	r := &Reader{fs: fs, dir: dir}
	for _, s := range segs {
		if s.Index >= from.Segment {
			r.segs = append(r.segs, s)
		}
	}
	r.i = -1
	if len(r.segs) > 0 && r.segs[0].Index == from.Segment {
		if err := r.load(0); err != nil {
			return nil, err
		}
		r.off = from.Offset
	}
	return r, nil
}

func (r *Reader) load(i int) error {
	b, err := r.fs.ReadFile(filepath.Join(r.dir, r.segs[i].Name))
	if err != nil {
		return err
	}
	r.i, r.data, r.off = i, b, 0
	return nil
}

// Next returns the next record and its position. It returns io.EOF after the
// last complete record, and ErrCorrupt at a damaged frame or at an
// incomplete frame that is followed by another segment.
func (r *Reader) Next() (Record, Position, error) {
	if r.err != nil {
		return Record{}, Position{}, r.err
	}
	for {
		if r.i < 0 || r.off >= int64(len(r.data)) {
			if r.i+1 >= len(r.segs) {
				return Record{}, Position{}, io.EOF
			}
			if err := r.load(r.i + 1); err != nil {
				r.err = err
				return Record{}, Position{}, err
			}
			continue
		}
		rec, n, torn, corrupt := decodeFrame(r.data[r.off:])
		switch {
		case corrupt || (torn && r.i+1 < len(r.segs)):
			r.err = fmt.Errorf("%w: segment %s offset %d", ErrCorrupt, r.segs[r.i].Name, r.off)
			return Record{}, Position{}, r.err
		case torn:
			return Record{}, Position{}, io.EOF
		}
		pos := Position{Segment: r.segs[r.i].Index, Offset: r.off}
		r.off += int64(n)
		return rec, pos, nil
	}
}

// ReadAll returns every readable record of dir from the beginning, stopping
// at the end or at the first damage (the error is then ErrCorrupt).
func ReadAll(fs fsys.FS, dir string) ([]Record, []Position, error) {
	r, err := OpenReader(fs, dir, Position{})
	if err != nil {
		return nil, nil, err
	}
	var recs []Record
	var pos []Position
	for {
		rec, p, err := r.Next()
		if err == io.EOF {
			return recs, pos, nil
		}
		if err != nil {
			return recs, pos, err
		}
		recs = append(recs, rec)
		pos = append(pos, p)
	}
}
