package journal

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/wal"
)

// WALReadRec retains the original bounded readable-prefix observation. It does
// not prove earlier WAL recovery repairs, persisted signer state, application
// execution or physical filesystem durability. Its wire value is separate v1.
type WALReadRec struct {
	Source       wal.ReadSource
	Mono, WallNs uint64
}
type walReadFrameRLP struct {
	Segment, Offset uint64
	Bytes           []byte
}
type walReadRLP struct {
	Format, JSeq, Version uint64
	Namespace             string
	Log, Sequence         uint64
	Error                 string
	Frames                []walReadFrameRLP
	Unavailable           string
	Mono, WallNs          uint64
}

var walReadCRC = crc32.MakeTable(crc32.Castagnoli)

func validWALReadRec(r *WALReadRec) bool {
	s := r.Source
	if s.Version != wal.ReadSourceVersion || r.Mono > math.MaxInt64 {
		return false
	}
	switch s.Error {
	case "", "corrupt", "read_error":
	default:
		return false
	}
	switch s.Unavailable {
	case "", "namespace_missing", "metadata_exhausted", "inspection_limits_required", "frame_limit", "byte_limit", "frame_encoding":
	default:
		return false
	}
	if s.Unavailable != "" && len(s.Frames) != 0 {
		return false
	}
	if s.Unavailable == "metadata_exhausted" {
		return s.Log == 0 || s.Sequence == 0
	}
	if s.Log == 0 || s.Sequence == 0 {
		return false
	}
	if (s.Namespace == "") != (s.Unavailable == "namespace_missing") {
		return false
	}
	var segment uint64
	var end int64
	for i, f := range s.Frames {
		if f.Position.Offset < 0 || len(f.Bytes) < 10 || uint64(len(f.Bytes)) > uint64(wal.MaxRecordBytes)+10 {
			return false
		}
		n := uint64(binary.BigEndian.Uint32(f.Bytes[:4]))
		if n+8 != uint64(len(f.Bytes)) || crc32.Checksum(f.Bytes[8:], walReadCRC) != binary.BigEndian.Uint32(f.Bytes[4:8]) {
			return false
		}
		if i == 0 || f.Position.Segment != segment {
			if f.Position.Offset != 0 || i > 0 && f.Position.Segment < segment {
				return false
			}
		} else if f.Position.Offset != end {
			return false
		}
		if int64(len(f.Bytes)) > math.MaxInt64-f.Position.Offset {
			return false
		}
		segment, end = f.Position.Segment, f.Position.Offset+int64(len(f.Bytes))
	}
	return true
}
func encodeWALReadRec(r *WALReadRec, jseq uint64) ([]byte, error) {
	if !validWALReadRec(r) {
		return nil, fmt.Errorf("journal: invalid WAL read source")
	}
	s := r.Source
	w := walReadRLP{Format: Format, JSeq: jseq, Version: s.Version, Namespace: s.Namespace, Log: s.Log, Sequence: s.Sequence, Error: s.Error, Unavailable: s.Unavailable, Mono: r.Mono, WallNs: r.WallNs}
	for _, f := range s.Frames {
		w.Frames = append(w.Frames, walReadFrameRLP{f.Position.Segment, uint64(f.Position.Offset), f.Bytes})
	}
	return rlp.Encode(&w)
}
func decodeWALReadRec(body []byte) (Record, error) {
	var w walReadRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: WAL read source: %v", ErrRecord, err)
	}
	if w.Format != Format {
		return Record{}, fmt.Errorf("%w: WAL read format", ErrRecord)
	}
	r := &WALReadRec{Source: wal.ReadSource{Version: w.Version, Namespace: w.Namespace, Log: w.Log, Sequence: w.Sequence, Error: w.Error, Unavailable: w.Unavailable}, Mono: w.Mono, WallNs: w.WallNs}
	for _, f := range w.Frames {
		if f.Offset > math.MaxInt64 {
			return Record{}, fmt.Errorf("%w: WAL read offset", ErrRecord)
		}
		r.Source.Frames = append(r.Source.Frames, wal.ReadSourceFrame{Position: wal.Position{Segment: f.Segment, Offset: int64(f.Offset)}, Bytes: f.Bytes})
	}
	if !validWALReadRec(r) {
		return Record{}, fmt.Errorf("%w: invalid WAL read source", ErrRecord)
	}
	return Record{Kind: KindWALRead, JSeq: w.JSeq, Body: r}, nil
}
