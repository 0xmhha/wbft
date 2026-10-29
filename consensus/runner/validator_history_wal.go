package runner

import "github.com/0xmhha/wbft/consensus/wal"

// appendFunctionalWAL keeps every functional writer behind one actor-owned
// profile seam. An absent selected writer preserves the original WAL method,
// durability request and returned physical position.
func (r *Runner) appendFunctionalWAL(record wal.Record, synchronous bool) (wal.Position, error) {
	if r.validatorWrite != nil {
		return r.validatorWrite(record, synchronous)
	}
	return r.appendOriginalFunctionalWAL(record, synchronous)
}

// appendOriginalFunctionalWAL is used by the validated profile's reserved
// writer as well as the unchanged default path; it never calls the hook again.
func (r *Runner) appendOriginalFunctionalWAL(record wal.Record, synchronous bool) (wal.Position, error) {
	if synchronous {
		return r.d.WAL.AppendSync(record)
	}
	return r.d.WAL.Append(record)
}
