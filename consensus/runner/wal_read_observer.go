package runner

import (
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

// WALReadSourceObserver sees detached original restore reads. It must return
// promptly. Reading evidence does not enable functional cache replay or prove
// an independently executed restored prefix, signer state or application state.
type WALReadSourceObserver interface{ ObserveWALRead(journal.WALReadRec) }

func (r *Runner) readReplayWAL() ([]wal.Record, []wal.Position, error) {
	if r.d.WALReadSources == nil {
		fs, dir := r.d.WAL.FS()
		return wal.ReadAll(fs, dir)
	}
	records, positions, source, err := r.d.WAL.ReadAllObserved(r.walReadNamespace, r.d.WALReadSourceLimits)
	r.lastWALReadSource = journal.WALReadRef{Namespace: source.Namespace, Log: source.Log, Sequence: source.Sequence}
	if s := r.restoreSource; s != nil {
		s.Read = journal.WALReadRef{Namespace: source.Namespace, Log: source.Log, Sequence: source.Sequence}
		if source.Unavailable != "" && s.Unavailable == "" {
			s.Unavailable = "source_unavailable"
		}
	}
	rec := journal.WALReadRec{Source: source, Mono: uint64(r.d.Clock.Mono()), WallNs: uint64(r.d.Clock.Now().UnixNano())}
	// ReadAllObserved already owns a separate bounded copy. No observer-owned
	// frame or namespace is subsequently used to select or execute the replay.
	r.d.WALReadSources.ObserveWALRead(rec)
	return records, positions, err
}
