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

func readReceiveFailureLimits(fs fsys.FS, path string) (journal.ReceiveFailureLimits, error) {
	var limits journal.ReceiveFailureLimits
	if path == "" {
		return limits, fmt.Errorf("check-receive-failures: --source-limits is required")
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
		return limits, fmt.Errorf("receive failure limits file exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return limits, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return limits, fmt.Errorf("receive failure limits require exactly one JSON object")
	}
	for _, value := range []uint64{limits.Caches, limits.Inbox.Operations, limits.Inbox.Entries, limits.Inbox.Peers, limits.Inbox.Frames, limits.Inbox.Bytes,
		limits.Inbox.Core.Records, limits.Inbox.Core.Runs, limits.Inbox.Core.Steps, limits.Inbox.Core.Environments, limits.Inbox.Core.Outputs, limits.Inbox.Core.Bytes} {
		if value == 0 {
			return limits, fmt.Errorf("check-receive-failures: all inspection limits must be positive")
		}
	}
	return limits, nil
}

// This loader retains original records without replacing hit bodies with checks.
// Segment decoding precedes the record limit; byte budgets are inspected after
// collection. These are finite inspection limits, not a process memory bound.
func checkReceiveFailures(fs fsys.FS, dir string, limits journal.ReceiveFailureLimits) (journal.ReceiveFailureCheck, error) {
	reader, err := journal.OpenReader(fs, dir)
	if err != nil {
		return journal.ReceiveFailureCheck{}, err
	}
	var records []journal.Record
	for {
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return journal.CheckReceiveFailureSources(records, limits)
		}
		if err != nil {
			return journal.ReceiveFailureCheck{}, err
		}
		if uint64(len(records)) >= limits.Inbox.Core.Records {
			return journal.ReceiveFailureCheck{Status: "unavailable", Reason: "record_limit", Scope: "original_failure_checks_bounded_cache_and_inbox_consumption", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}, nil
		}
		records = append(records, record)
	}
}
