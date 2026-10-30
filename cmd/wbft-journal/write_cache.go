package main

import (
	"errors"
	"io"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func readCacheMetadata(fs fsys.FS, dir string, maxRecords uint64) ([]journal.Record, bool, error) {
	reader, err := journal.OpenReader(fs, dir)
	if err != nil {
		return nil, false, err
	}
	var records []journal.Record
	var read uint64
	for {
		record, err := readSourceRecord(reader)
		if errors.Is(err, io.EOF) {
			return records, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if read >= maxRecords {
			return nil, false, nil
		}
		read++
		switch record.Body.(type) {
		case *journal.SegmentRec, *journal.GapRec, *journal.WriteCacheRec, *journal.ReceiveCacheRec:
			records = append(records, record)
		}
	}
}
func checkWriteCache(fs fsys.FS, dir string, limits journal.WriteCacheCheckLimits) (journal.WriteCacheCheck, error) {
	records, complete, err := readCacheMetadata(fs, dir, limits.Records)
	if err != nil {
		return journal.WriteCacheCheck{}, err
	}
	if !complete {
		return journal.WriteCacheCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable"}, nil
	}
	return journal.CheckWriteCacheTransitions(records, limits)
}
func checkReceiveCache(fs fsys.FS, dir string, limits journal.ReceiveCacheCheckLimits) (journal.ReceiveCacheCheck, error) {
	records, complete, err := readCacheMetadata(fs, dir, limits.Records)
	if err != nil {
		return journal.ReceiveCacheCheck{}, err
	}
	if !complete {
		return journal.ReceiveCacheCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable"}, nil
	}
	return journal.CheckReceiveCacheTransitions(records, limits)
}
