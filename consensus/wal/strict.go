package wal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/0xmhha/wbft/internal/fsys"
)

// ErrSourceChanged refuses materialization when the inspected prefix changed.
var ErrSourceChanged = errors.New("wal: inspected source changed")

// Snapshot is a complete, read-only frame inspection. It requires exclusive
// ownership of the WAL directory until Open returns; it is not a filesystem
// lock or a guarantee against concurrent external writes.
type Snapshot struct {
	fs        fsys.FS
	dir       string
	digest    [32]byte
	records   []Record
	positions []Position
	segments  int
	next      uint64
}

// Inspect reads every frame without creating, repairing or syncing files.
// Unlike ReadAll, it rejects even an incomplete final frame and refuses a
// directory containing a segment previously moved aside as corrupted.
func Inspect(fs fsys.FS, dir string) (*Snapshot, error) {
	names, err := fs.ReadDir(dir)
	exists := true
	if fsys.IsNotExist(err) {
		names, err, exists = nil, nil, false
	}
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	s := &Snapshot{fs: fs, dir: dir}
	h := sha256.New()
	_, _ = h.Write([]byte("wal-strict-prefix-v1"))
	if exists {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	for _, name := range names {
		if _, marker := segmentIndex(strings.TrimSuffix(name, corruptedSuffix)); marker && strings.HasSuffix(name, corruptedSuffix) {
			return nil, fmt.Errorf("%w: moved-aside segment %s", ErrCorrupt, name)
		}
		index, ok := segmentIndex(name)
		if !ok {
			continue
		}
		if index == math.MaxUint64 {
			return nil, fmt.Errorf("wal: segment index exhausted")
		}
		path := filepath.Join(dir, name)
		size, err := fs.Size(path)
		if err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if size != int64(len(b)) {
			return nil, ErrSourceChanged
		}
		result := scan(b)
		if result.torn || result.corrupt {
			return nil, fmt.Errorf("%w: incomplete or damaged segment %s", ErrCorrupt, name)
		}
		var header [16]byte
		binary.BigEndian.PutUint64(header[:8], index)
		binary.BigEndian.PutUint64(header[8:], uint64(len(b)))
		_, _ = h.Write(header[:])
		_, _ = h.Write(b)
		var offset int64
		for i, record := range result.records {
			s.records = append(s.records, record)
			s.positions = append(s.positions, Position{Segment: index, Offset: offset})
			offset = result.ends[i]
		}
		s.segments++
		s.next = index + 1
	}
	copy(s.digest[:], h.Sum(nil))
	return s, nil
}

// Records returns detached records and positions of the inspected prefix.
func (s *Snapshot) Records() ([]Record, []Position) {
	records := slices.Clone(s.records)
	for i := range records {
		records[i].Body = bytes.Clone(records[i].Body)
	}
	return records, slices.Clone(s.positions)
}

// Open rechecks the complete prefix before the first write, then starts a
// new exclusive segment. It never repairs, renames or truncates old files.
// A zero Snapshot cannot authorize an open.
func (s *Snapshot) Open(opt Options) (*Log, Recovery, error) {
	var rec Recovery
	if s == nil || s.fs == nil {
		return nil, rec, errors.New("wal: missing strict snapshot")
	}
	current, err := Inspect(s.fs, s.dir)
	if err != nil {
		return nil, rec, err
	}
	if current.digest != s.digest {
		return nil, rec, ErrSourceChanged
	}
	if opt.SegmentBytes <= 0 {
		opt.SegmentBytes = DefaultSegmentBytes
	}
	if opt.KeepHeights <= 0 {
		opt.KeepHeights = 2
	}
	if err := s.fs.MkdirAll(s.dir, 0o700); err != nil {
		return nil, rec, err
	}
	rec.Segments, rec.Records = s.segments, len(s.records)
	l := &Log{fs: s.fs, dir: s.dir, opt: opt, seg: s.next, strict: true}
	if err := l.startSegment(s.next); err != nil {
		return nil, rec, err
	}
	return l, rec, nil
}

// OpenStrict inspects and opens a WAL without repair. Application profiles
// must validate Snapshot.Records before calling Snapshot.Open instead.
func OpenStrict(fs fsys.FS, dir string, opt Options) (*Log, Recovery, error) {
	s, err := Inspect(fs, dir)
	if err != nil {
		return nil, Recovery{}, err
	}
	return s.Open(opt)
}

// OpenStrictOS provides the non-repairing open for external integrations.
func OpenStrictOS(dir string, opt Options) (*Log, Recovery, error) {
	return OpenStrict(fsys.OS{}, dir, opt)
}

// OpenedStrict reports whether the log was opened without a repair path.
func (l *Log) OpenedStrict() bool { return l != nil && l.strict }
