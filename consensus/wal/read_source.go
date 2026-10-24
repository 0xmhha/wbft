package wal

import (
	"errors"
	"sync"
	"sync/atomic"
)

const ReadSourceVersion uint64 = 1

// ReadSourceLimits bound copied diagnostic frames and wire bytes. They do not
// bound the original ReadAll allocations, filesystem reads or runtime retention.
type ReadSourceLimits struct{ Frames, Bytes uint64 }

// ReadSourceFrame is the exact canonical encoding of a frame already verified
// by the original reader, at its original segment and byte offset. It makes no
// claim about an unread tail, earlier recovery repairs or physical durability.
type ReadSourceFrame struct {
	Position Position
	Bytes    []byte
}

// ReadSource retains one original ReadAll result. Namespace is fixed at this
// Log's first observed read, including when empty. It qualifies observed reads,
// not earlier writes or an otherwise unobserved writer's identity.
type ReadSource struct {
	Version       uint64
	Namespace     string
	Log, Sequence uint64
	Error         string
	Frames        []ReadSourceFrame
	Unavailable   string
}
type readSourceState struct {
	mu            sync.Mutex
	initialized   bool
	namespace     string
	log, sequence uint64
	exhausted     bool
}

var readSourceLogIDs atomic.Uint64

func nextReadSourceLogID() uint64 {
	for {
		previous := readSourceLogIDs.Load()
		if previous == ^uint64(0) {
			return 0
		}
		if readSourceLogIDs.CompareAndSwap(previous, previous+1) {
			return previous + 1
		}
	}
}
func (l *Log) beginReadSource(namespace string) ReadSource {
	s := &l.readSource
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		s.initialized = true
		s.namespace = namespace
		s.log = nextReadSourceLogID()
	}
	if s.sequence == ^uint64(0) {
		s.exhausted = true
	} else if !s.exhausted {
		s.sequence++
	}
	sequence := s.sequence
	if s.exhausted {
		sequence = 0
	}
	out := ReadSource{Version: ReadSourceVersion, Namespace: s.namespace, Log: s.log, Sequence: sequence}
	if out.Namespace == "" {
		out.Unavailable = "namespace_missing"
	}
	if out.Log == 0 || out.Sequence == 0 {
		out.Unavailable = "metadata_exhausted"
	}
	return out
}

// ReadAllObserved calls the original reader exactly once and preserves its
// records, positions and error. Only a bounded detached diagnostic copy is
// added. No original WAL mutex spans the filesystem read or diagnostic work.
// Sequence orders entry into observed reads, not completion of concurrent reads.
func (l *Log) ReadAllObserved(namespace string, limits ReadSourceLimits) ([]Record, []Position, ReadSource, error) {
	source := l.beginReadSource(namespace)
	records, positions, err := ReadAll(l.fs, l.dir)
	if err != nil {
		source.Error = "read_error"
		if errors.Is(err, ErrCorrupt) {
			source.Error = "corrupt"
		}
	}
	if source.Unavailable != "" {
		return records, positions, source, err
	}
	if limits.Frames == 0 || limits.Bytes == 0 {
		source.Unavailable = "inspection_limits_required"
		return records, positions, source, err
	}
	if uint64(len(records)) > limits.Frames {
		source.Unavailable = "frame_limit"
		return records, positions, source, err
	}
	var span uint64
	for _, record := range records {
		n := uint64(headerLen+2) + uint64(len(record.Body))
		if n > limits.Bytes-span {
			source.Unavailable = "byte_limit"
			return records, positions, source, err
		}
		span += n
	}
	source.Frames = make([]ReadSourceFrame, len(records))
	for i, record := range records {
		encoded, e := Encode(record)
		if e != nil {
			source.Frames = nil
			source.Unavailable = "frame_encoding"
			return records, positions, source, err
		}
		source.Frames[i] = ReadSourceFrame{positions[i], encoded}
	}
	return records, positions, source, err
}
