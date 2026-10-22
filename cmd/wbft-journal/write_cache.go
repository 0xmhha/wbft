package main

import (
	"errors"
	"io"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func checkWriteCache(fs fsys.FS, dir string, limits journal.WriteCacheCheckLimits) (journal.WriteCacheCheck, error) {
	reader, err := journal.OpenReader(fs, dir)
	if err != nil {
		return journal.WriteCacheCheck{}, err
	}
	var records []journal.Record
	var read uint64
	for {
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return journal.WriteCacheCheck{}, err
		}
		if read >= limits.Records {
			return journal.WriteCacheCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable"}, nil
		}
		read++
		// Payloads and unrelated consensus records are not retained by this check.
		switch record.Body.(type) {
		case *journal.SegmentRec, *journal.GapRec, *journal.WriteCacheRec:
			records = append(records, record)
		}
	}
	return journal.CheckWriteCacheTransitions(records, limits)
}
