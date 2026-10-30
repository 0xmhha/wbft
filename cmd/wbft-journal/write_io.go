package main

import (
	"errors"
	"io"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// Reader.Next decodes a WAL segment before this metadata cap is applied. These
// limits bound inspection indexes, not segment allocation or payload heap.
// Unrelated payloads are discarded after decoding. EOF is a readable prefix,
// not proof that no further writes or torn tail exist outside this evidence.
func checkWriteIO(fs fsys.FS, dir string, limits journal.WriteIOCheckLimits) (journal.WriteIOCheck, error) {
	reader, err := journal.OpenReader(fs, dir)
	if err != nil {
		return journal.WriteIOCheck{}, err
	}
	var records []journal.Record
	var count uint64
	var frames uint64
	for {
		record, err := readSourceRecord(reader)
		if errors.Is(err, io.EOF) {
			return journal.CheckWriteIOSources(records, limits)
		}
		if err != nil {
			return journal.WriteIOCheck{}, err
		}
		if count >= limits.Records {
			return journal.WriteIOCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable"}, nil
		}
		count++
		switch b := record.Body.(type) {
		case *journal.SegmentRec, *journal.PeerRec, *journal.SessionRec, *journal.WriteCacheRec, *journal.GapRec:
			records = append(records, record)
		case *journal.MsgRec:
			if b.WriteAttempt != nil {
				if frames >= limits.Frames {
					return journal.WriteIOCheck{Status: "unavailable", Reason: "frame_limit", PhysicalStatus: "unavailable"}, nil
				}
				frames++
				records = append(records, record)
			}
		}
	}
}
