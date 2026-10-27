package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// A limits file is a small explicit inspection configuration. It supplies no
// operating retry maximum, key, wire message or functional replay authority.
func readRetryLimits(fs fsys.FS, path string) (journal.RetrySourceLimits, error) {
	var limits journal.RetrySourceLimits
	if path == "" {
		return limits, fmt.Errorf("check-round-change-retry: --source-limits is required")
	}
	f, err := fs.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return limits, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return limits, err
	}
	if len(raw) > 65536 {
		return limits, fmt.Errorf("retry source limits file exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return limits, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return limits, fmt.Errorf("retry source limits require exactly one JSON object")
	}
	return limits, limits.Validate()
}

// Reader.Next decodes original segments before these inspection limits are
// applied. They bound retained checker inputs, not segment allocations, process
// heap or a live node. EOF is the readable prefix rather than a durability claim.
func checkRoundChangeRetry(fs fsys.FS, dir string, limits journal.RetrySourceLimits) (journal.RetrySourceCheck, error) {
	reader, err := journal.OpenReader(fs, dir)
	if err != nil {
		return journal.RetrySourceCheck{}, err
	}
	var records []journal.Record
	var count uint64
	for {
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return journal.CheckRoundChangeRetrySources(records, limits)
		}
		if err != nil {
			return journal.RetrySourceCheck{}, err
		}
		if count >= limits.Timers.Core.Records {
			return journal.RetrySourceCheck{Status: "unavailable", Reason: "record_limit", PhysicalStatus: "unavailable", Scope: "original_retry_owner_timer_signer_wal_cache_bindings"}, nil
		}
		count++
		switch record.Body.(type) {
		case *journal.SegmentRec, *journal.GapRec, *journal.CoreStepRec, *journal.TimerRec, *journal.SignerRec,
			*journal.SignerCallRec, *journal.WALReadRec, *journal.RestoreRec, *journal.CacheRec, *journal.WriteCacheRec:
			records = append(records, record)
		}
	}
}
