package main

import (
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestCheckReceiveCacheCommandRetainsDistinctOutcome(t *testing.T) {
	fs := fsys.NewMem()
	limits := transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}
	writer, err := journal.Open(journal.Options{FS: fs, Dir: "/receive-command", Synchronous: true}, journal.Identity{Run: "receive-command", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}}})
	if err != nil {
		t.Fatal(err)
	}
	option := limits.ReceiveOptions()
	option.Trace = unsupportedReceiveRecordObserver{writer}
	ledger, err := transport.NewReceiveLedger(option)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var check journal.ReceiveCacheCheck
	args := []string{"check-receive-cache", "--dir", "/receive-command", "--max-records", "100", "--max-ledgers", "4", "--max-reordered", "4"}
	runJSON(t, fs, 0, &check, args...)
	if check.Status != "consistent" || check.PhysicalStatus != "unavailable" || check.Ledgers != 1 {
		t.Fatal(check)
	}
	runJSON(t, fs, 2, nil, "check-receive-cache", "--dir", "/receive-command")
	args[4] = "1"
	runJSON(t, fs, 69, &check, args...)
	if check.Reason != "record_limit" {
		t.Fatal(check)
	}
	writeJournal(t, fs)
	runJSON(t, fs, 69, &check, "check-receive-cache", "--dir", "/j", "--max-records", "1000", "--max-ledgers", "4", "--max-reordered", "4")
	if check.Reason != "no_receive_cache_trace" {
		t.Fatal(check)
	}
}
