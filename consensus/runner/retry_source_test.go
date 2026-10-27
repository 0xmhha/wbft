package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type normalRetrySources struct {
	writer journal.Writer
	clock  *manualClock
	run    string
}

func (o *normalRetrySources) CaptureRun() string { return o.run }
func (o *normalRetrySources) ObserveCoreStep(s journal.CoreStepRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *normalRetrySources) ObserveTimerSource(s journal.TimerRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *normalRetrySources) ObserveSignerCall(s journal.SignerCallRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *normalRetrySources) ObserveWALRead(s journal.WALReadRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *normalRetrySources) ObserveRestore(s journal.RestoreRec) {
	o.writer.Put(journal.Record{Body: &s})
}

func (o *normalRetrySources) ObserveWriteTransition(s transport.WriteTransition) {
	o.writer.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: s, Mono: o.clock.Mono(), WallNs: o.clock.Now().UnixNano()}})
}

// This queue fixture reports ordinary successful completions. It does not
// stand in for the SDK adapter's actual WriteMsg validation.
type normalRetryCompletedTransport struct {
	*fakeNet
	targets []transport.WritePeer
}

func (tr normalRetryCompletedTransport) WritePeers() []transport.WritePeer { return tr.targets }
func (tr normalRetryCompletedTransport) SendWrite(target transport.WritePeer, code uint64, payload []byte, _ transport.SendAttempt, done func(transport.WriteReceipt)) transport.SendResult {
	tr.Send([]types.Address{target.Addr}, code, payload)
	done(transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(payload), Result: transport.LocalWriteOK})
	return transport.Queued
}
func (o *normalRetrySources) signer(s privval.Source) {
	o.writer.Put(journal.Record{Body: &journal.SignerRec{Source: s, Mono: uint64(o.clock.Mono()), WallNs: uint64(o.clock.Now().UnixNano())}})
}

type normalRetryCacheTransport struct {
	*fakeNet
	source *normalRetrySources
}

func (tr normalRetryCacheTransport) BeginCache(self types.Address) uint64 {
	tr.source.writer.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Action: "begin", Self: self, PeerCapacity: transport.InmemoryPeers, MessageCapacity: transport.InmemoryMessages}})
	return 1
}
func (tr normalRetryCacheTransport) CacheOperation(op transport.CacheOperation) {
	tr.source.writer.Put(journal.Record{Body: &journal.CacheRec{Retry: op.Retry, Instance: op.Instance, Sequence: op.Sequence, Action: op.Action,
		Peer: op.Peer, Code: op.Code, Key: op.Key, PayloadSHA256: op.PayloadSHA256, Cause: op.Cause, Known: op.Known, Recent: op.Recent, Available: op.Available,
		Candidates: op.Candidates, Targets: op.Targets, Suppressed: op.Suppressed, Mono: tr.source.clock.Mono(), WallNs: tr.source.clock.Now().UnixNano()}})
}

func TestNormalRetryIndependentTimerSignerWALSources(t *testing.T) {
	for _, completed := range []bool{false, true} {
		for _, prior := range []bool{false, true} {
			t.Run(fmt.Sprintf("completed=%t/prior=%t", completed, prior), func(t *testing.T) { normalRetryIndependentSources(t, completed, prior) })
		}
	}
}

func normalRetryIndependentSources(t *testing.T, completed, prior bool) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 3)
	raw := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	cfg, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	n.opts.Config, n.opts.RoundChangeRetry = cfg, &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
	if prior {
		n.opts.Improvements = n.opts.Improvements.With(consensus.BindPriorHead)
	}
	n.noJournal = true
	id := journal.Identity{Self: k.addrs[3], Run: "normal-retry-sources", Core: journal.CoreOptions{Self: k.addrs[3], ChainConfig: raw, Improvements: uint64(n.opts.Improvements), TimerTrace: journal.TimerTraceVersion,
		RoundChangeRetry: &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 8000}}}
	if completed {
		id.Core.CachePolicy = &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}}
	}
	w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/retry-sources", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	o := &normalRetrySources{writer: w, clock: n.clock, run: id.Run}
	n.coreSteps, n.timerSources, n.signerCalls, n.walReadSources = o, o, o, o
	n.walReadSourceLimits = wal.ReadSourceLimits{Frames: 10000, Bytes: 8 << 20}
	n.signerSources = &privval.SourceOptions{Namespace: id.Run, Records: 10000, Bytes: 8 << 20, Observe: o.signer}
	n.dedupTransport = normalRetryCacheTransport{fakeNet: n.net, source: o}
	factor := uint64(1)
	if completed {
		limits := id.Core.CachePolicy.Limits
		write, receive := limits.WriteOptions(), limits.ReceiveOptions()
		write.Trace = o
		n.receiveCache = &receive
		n.dedupOptions = &transport.DedupOptions{Self: k.addrs[3], RoundChangeRetry: true, KeyWithCode: true, RecordAfterSend: true, CompletedWrites: &write}
		tr := normalRetryCompletedTransport{fakeNet: n.net}
		for _, peer := range n.net.peers {
			tr.targets = append(tr.targets, transport.WritePeer{Addr: peer, Session: transport.NewWriteSession()})
		}
		n.dedupTransport = tr
		factor = uint64(len(tr.targets))
	}
	n.boot()
	t.Cleanup(func() { _ = n.r.Close(); _ = n.log.Close() })
	for range 6 {
		n.advance(n.r.timers.live[consensus.RoundTimer].arm.Duration)
	}
	for _, delay := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second} {
		n.advance(delay)
	}
	before := *n.r.Vars().RoundChangeRetry
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	n.r.Pump()
	after := n.r.Vars().RoundChangeRetry
	if !n.r.LastReplay().Replayed || after == nil || after.Key != before.Key || after.Exponent != before.Exponent || after.View.Cmp(before.View) != 0 {
		t.Fatal("normal pause/replay changed retry state", n.r.LastReplay(), after)
	}
	n.advance(8 * time.Second)
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	// Original bounded read, after writes; no copied frame is supplied to
	// live replay. This provides the later exact own-WAL byte witnesses.
	if _, _, err := n.r.readReplayWAL(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/retry-sources")
	if err != nil {
		t.Fatal(err)
	}
	core := journal.CoreSourceLimits{Records: 10000, Runs: 8, Steps: 1000, Environments: 10000, Outputs: 10000, Bytes: 16 << 20}
	limits := journal.RetrySourceLimits{Timers: journal.TimerSourceLimits{Core: core, Operations: 10000, Bindings: 10000, Bytes: 16 << 20}, Signer: privval.SourceLimits{Lifetimes: 8, Operations: 10000, Records: 10000, Bytes: 16 << 20}, Writes: journal.WriteCacheCheckLimits{Records: 10000, Ledgers: 8, Reordered: 128}}
	check, err := journal.CheckRoundChangeRetrySources(records, limits)
	if err != nil || check.Status != "consistent" || check.Retries < 4 || check.Decisions != check.Retries*factor || check.PhysicalStatus != "unavailable" {
		t.Fatal("independent normal retry source join", check, err)
	}
	if cli := os.Getenv("WBFT_RETRY_SOURCE_CLI"); cli != "" {
		checkNormalRetrySourceCLI(t, cli, n.jfs, limits, check)
	}
	// Read-only projections model unavailable diagnostic qualifications. The
	// original actors, signer, network and WAL have already ended unchanged.
	missing := append([]journal.Record(nil), records...)
	for i, record := range missing {
		if op, ok := record.Body.(*journal.CacheRec); ok && op.Retry.Version != 0 {
			copy := *op
			copy.Retry.EngineRun, copy.Retry.Step, copy.Retry.Output = 0, 0, 0
			missing[i].Body = &copy
		}
		if op, ok := record.Body.(*journal.WriteCacheRec); ok && op.Transition.Retry.Version != 0 {
			copy := *op
			copy.Transition.Retry.EngineRun, copy.Transition.Retry.Step, copy.Transition.Retry.Output = 0, 0, 0
			missing[i].Body = &copy
		}
	}
	check, err = journal.CheckRoundChangeRetrySources(missing, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "original_retry_owner_missing" {
		t.Fatal("missing qualification became source authority", check, err)
	}
	for index, record := range records {
		op, ok := record.Body.(*journal.CacheRec)
		if !ok || op.Retry.Version == 0 {
			continue
		}
		// Offline reader shape checks only; the original actors and all
		// their bytes remain closed and are never fed these projections.
		duplicate := append(append([]journal.Record(nil), records...), record)
		check, err = journal.CheckRoundChangeRetrySources(duplicate, limits)
		if err == nil || check.Status != "inconsistent" || check.Reason != "retry_gossip_decision_repeated_or_mixed" {
			t.Fatal("repeated owner decision accepted", check, err)
		}
		for _, projection := range []string{"outside-step", "targets-differ"} {
			copy := *op
			if projection == "outside-step" {
				copy.Mono--
			} else {
				copy.Targets = nil
			}
			projected := append([]journal.Record(nil), records...)
			projected[index].Body = &copy
			check, err = journal.CheckRoundChangeRetrySources(projected, limits)
			if err == nil || check.Status != "inconsistent" {
				t.Fatal("unbound decision metadata accepted", projection, check, err)
			}
		}
		break
	}
}

// An explicitly supplied prebuilt command allows end-to-end CLI validation
// on the same original normal source bytes. The test never builds a nested Go
// tool or writes outside its owned TempDir. Ordinary API checks need no binary.
func checkNormalRetrySourceCLI(t *testing.T, cli string, fs fsys.FS, limits journal.RetrySourceLimits, expected journal.RetrySourceCheck) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	names, err := fs.ReadDir("/retry-sources")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if filepath.Base(name) != name {
			t.Fatal("non-local fixture name")
		}
		raw, err := fs.ReadFile(filepath.Join("/retry-sources", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "limits.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), cli, "check-round-change-retry", "--dir", dir, "--source-limits", path).CombinedOutput()
	if err != nil {
		t.Fatalf("source CLI failed: %v\n%s", err, output)
	}
	var got journal.RetrySourceCheck
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatal("CLI changed the independent source verdict", got, expected)
	}
	t.Logf("source CLI exit 0 on original normal sources: retries=%d decisions=%d", got.Retries, got.Decisions)
}
