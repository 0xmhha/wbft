package journal

import (
	"errors"
	"fmt"
	"io"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

var ErrCaptureMissing = errors.New("journal: captured input record is missing")

var ErrCapture = errors.New("journal: captured input unavailable or ambiguous")

type captureKey struct {
	run string
	id  uint64
}
type capturePosition struct {
	pos       wal.Position
	peer      types.Address
	ambiguous bool
}

// CapturedFrame is an original received record and its explicitly mapped peer.
type CapturedFrame struct {
	Record *MsgRec
	Peer   types.Address
}

// ResolveCapture uses a bounded, position-only index. It supports records
// written after their steps without caching payloads for the whole journal.
func (r *Reader) ResolveCapture(run string, id uint64) (CapturedFrame, error) {
	if !r.indexed {
		r.indexed = true
		r.captureErr = r.indexCaptures()
	}
	if r.captureErr != nil {
		return CapturedFrame{}, r.captureErr
	}
	p, ok := r.captures[captureKey{run, id}]
	if !ok {
		return CapturedFrame{}, ErrCaptureMissing
	}
	if p.ambiguous || p.peer == (types.Address{}) {
		return CapturedFrame{}, ErrCapture
	}
	reader, err := wal.OpenReader(r.fs, r.dir, p.pos)
	if err != nil {
		return CapturedFrame{}, err
	}
	raw, _, err := reader.Next()
	if err != nil {
		return CapturedFrame{}, err
	}
	rec, err := decodeBody(Kind(raw.Kind), raw.Body)
	if err != nil {
		return CapturedFrame{}, err
	}
	m, ok := rec.Body.(*MsgRec)
	if !ok || m.Dir != In || m.Capture != id || m.Size > uint64(len(m.Payload)) {
		return CapturedFrame{}, ErrCapture
	}
	return CapturedFrame{Record: m, Peer: p.peer}, nil
}
func (r *Reader) indexCaptures() error {
	reader, err := OpenReader(r.fs, r.dir)
	if err != nil {
		return err
	}
	r.captures = map[captureKey]capturePosition{}
	peers := map[uint32]types.Address{}
	run := ""
	for count := 0; ; count++ {
		rec, pos, err := reader.NextAt()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= 1000000 {
			return fmt.Errorf("%w: record limit exceeded", ErrCapture)
		}
		switch m := rec.Body.(type) {
		case *SegmentRec:
			if m.Run != run {
				run = m.Run
				peers = map[uint32]types.Address{}
			}
		case *PeerRec:
			if m.Event == "attached" {
				peers[m.PeerIdx] = m.Addr
			}
		case *MsgRec:
			if m.Dir == In && m.Capture != 0 {
				k := captureKey{run, m.Capture}
				p := capturePosition{pos: pos, peer: peers[m.PeerIdx]}
				if _, ok := r.captures[k]; ok {
					p.ambiguous = true
				}
				r.captures[k] = p
			}
		}
	}
}
