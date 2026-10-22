package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// SessionRef names an observation of a process-local stream. Run is the first
// recorder to qualify that stream; it may differ from the current segment run.
// It is not validator authority, a remote acknowledgement or a delivery proof.
// Missing provenance is represented by a nil reference, never a partial name.
type SessionRef struct {
	Run     string
	Ordinal uint64
}

// SessionRec reports an adapter's observation or functional end of a session.
// "observed" registers an existing lifetime; it does not recover attach time.
// Active is sampled at the callback, whose order may differ from loop endings.
type SessionRec struct {
	Session *SessionRef
	Peer    types.Address
	Event   string
	Active  bool
	Mono    time.Duration
	WallNs  int64
}

const SessionObserved = "observed"

type sessionRefRLP struct {
	Profile uint64
	Run     string
	Ordinal uint64
}

func encodeSessionRef(ref *SessionRef) ([]sessionRefRLP, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.Run == "" || ref.Ordinal == 0 {
		return nil, fmt.Errorf("journal: incomplete session reference")
	}
	return []sessionRefRLP{{Profile: 1, Run: ref.Run, Ordinal: ref.Ordinal}}, nil
}

func decodeSessionRef(w []sessionRefRLP) (*SessionRef, error) {
	if len(w) == 0 {
		return nil, nil
	}
	if len(w) != 1 || w[0].Profile != 1 || w[0].Run == "" || w[0].Ordinal == 0 {
		return nil, fmt.Errorf("journal: invalid session reference")
	}
	return &SessionRef{Run: w[0].Run, Ordinal: w[0].Ordinal}, nil
}

type sessionRLP struct {
	Format, JSeq uint64
	Session      []sessionRefRLP
	Peer         types.Address
	Event        string
	Active       uint64
	Mono, WallNs uint64
}

func validSessionEvent(event string, active bool) bool {
	switch event {
	case SessionObserved:
		return true
	case string(transport.SessionWriterEnded), string(transport.SessionRemoved):
		return !active
	}
	return false
}

func encodeSessionRec(r *SessionRec, jseq uint64) ([]byte, error) {
	ref, err := encodeSessionRef(r.Session)
	if err != nil {
		return nil, err
	}
	if !validSessionEvent(r.Event, r.Active) {
		return nil, fmt.Errorf("journal: invalid session observation")
	}
	return rlp.Encode(&sessionRLP{Format: Format, JSeq: jseq, Session: ref,
		Peer: r.Peer, Event: r.Event, Active: boolUint(r.Active), Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}

func decodeSessionRec(body []byte) (Record, error) {
	var w sessionRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: session: %v", ErrRecord, err)
	}
	ref, err := decodeSessionRef(w.Session)
	if err != nil || w.Format != Format || w.Active > 1 || !validSessionEvent(w.Event, w.Active != 0) {
		return Record{}, fmt.Errorf("%w: invalid session observation", ErrRecord)
	}
	return Record{Kind: KindSession, JSeq: w.JSeq, Body: &SessionRec{Session: ref,
		Peer: w.Peer, Event: w.Event, Active: w.Active != 0, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}}, nil
}
