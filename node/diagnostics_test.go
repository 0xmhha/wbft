package node

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// No attached peers: this fixture exercises actual Node/core/app/signing paths,
// and makes no physical I/O or remote-delivery claim.
type diagnosticIsolatedTransport struct{ cacheIsolatedTransport }

func (*diagnosticIsolatedTransport) SetFrameObserver(transport.FrameObserver) {}
func (*diagnosticIsolatedTransport) WritePeers() []transport.WritePeer        { return nil }
func (*diagnosticIsolatedTransport) SendWrite(transport.WritePeer, uint64, []byte, transport.SendAttempt, func(transport.WriteReceipt)) transport.SendResult {
	panic("no attached peer can request a physical write")
}

type sourceFinalizingApp struct {
	*testApp
	sourceMu   sync.Mutex
	requests   []app.FinalizeSource
	unobserved int
}

func (a *sourceFinalizingApp) FinalizeBlock(ctx context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	a.sourceMu.Lock()
	if req.Source == nil {
		a.unobserved++
	} else {
		a.requests = append(a.requests, *req.Source)
	}
	a.sourceMu.Unlock()
	return a.testApp.FinalizeBlock(ctx, req)
}

func TestNodeDiagnosticsNormalColdAndStoredSources(t *testing.T) {
	key := testKey(0)
	config, genesis := testGenesis(t, key)
	parsed, err := types.ParseChainConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	a := &sourceFinalizingApp{testApp: newTestApp(config, genesis)}
	fs := fsys.NewMem()
	limits := transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}
	for run := 0; run < 2; run++ {
		runID := fmt.Sprintf("normal-node-%d", run)
		dir := "/diagnostic-" + runID
		w, err := journal.Open(journal.Options{FS: fs, Dir: dir, Synchronous: true}, journal.Identity{Run: runID, Core: journal.CoreOptions{
			Self: parsed.Init.Validators[0], ChainConfig: config, Improvements: uint64(consensus.RestartSafety), TimerTrace: journal.TimerTraceVersion,
			CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits},
		}})
		if err != nil {
			t.Fatal(err)
		}
		options := &DiagnosticOptions{Writer: w, WALRead: wal.ReadSourceLimits{Frames: 4096, Bytes: 8 << 20}, SignerRecords: 4096, SignerBytes: 8 << 20, ApplicationBytes: 8 << 20, WALReadOnStop: true}
		n, err := New(Config{DataDir: "/data", RunID: runID, CachePolicy: &limits, Journal: JournalConfig{Disabled: true}}, Deps{
			App: a, Authority: a, fs: fs, key: key, Transport: &diagnosticIsolatedTransport{}, Diagnostics: options,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Options are caller-owned; Node froze the source configuration at New.
		options.SignerBytes, options.WALRead.Bytes = 1, 1
		options.WALReadOnStop = false
		a.cons = n.Consensus()
		target := a.Head().Number.RefLow64() + 1 //wbft:low64 HH-60
		if err = n.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(t, n) })
		a.waitHead(t, target, 20*time.Second)
		if err = n.Stop(); err != nil {
			t.Fatal(err)
		}
		if n.journal != nil {
			t.Fatal("diagnostics installed functional journal")
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := journal.ReadAll(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[journal.Kind]int{}
		readSources := 0
		for _, row := range rows {
			if source, ok := row.Body.(*journal.WALReadRec); ok {
				readSources++
				if source.Source.Unavailable != "" || source.Source.Error != "" {
					t.Fatal("original shutdown read unavailable", source)
				}
			}
		}
		if readSources != 2 {
			t.Fatal("frozen explicit shutdown read not retained", readSources)
		}
		owners := map[uint64]journal.FinalizeRec{}
		for _, row := range rows {
			counts[row.Kind]++
			switch s := row.Body.(type) {
			case *journal.GapRec:
				t.Fatal("unexpected diagnostic loss", s)
			case *journal.WALReadRec:
				if s.Source.Namespace != runID || s.Source.Unavailable != "" {
					t.Fatal("actual read source missing", s)
				}
			case *journal.SignerRec:
				if s.Source.Ref.Namespace != runID || s.Source.Unavailable != "" {
					t.Fatal("original signer source missing", s)
				}
			case *journal.SignerCallRec:
				if s.Source.Namespace != runID || s.Unavailable != "" || s.WALWritten != 1 {
					t.Fatal("actual signer/WAL call missing", s)
				}
			case *journal.FinalizeRec:
				if s.Action == "enter" {
					owners[s.Task] = *s
				}
			}
		}
		for _, kind := range []journal.Kind{journal.KindCoreStep, journal.KindTimer, journal.KindAppQueue, journal.KindFinalize, journal.KindInternal, journal.KindSelection, journal.KindWALRead, journal.KindRestore, journal.KindSigner, journal.KindSignerCall, journal.KindApplication} {
			if counts[kind] == 0 {
				t.Fatal("actual Node source not forwarded", kind, counts)
			}
		}

		bounds := journal.FinalizeLimits{Queue: journal.AppQueueLimits{Core: journal.CoreSourceLimits{Records: 20000, Runs: 32, Steps: 20000, Environments: 20000, Outputs: 100000, Bytes: 64 << 20}, Operations: 20000, Entries: 20000, Bytes: 64 << 20}, Operations: 20000, Tasks: 20000, Bytes: 64 << 20}
		checked, checkErr := journal.CheckFinalizeSources(rows, bounds)
		if checkErr != nil || checked.Status != "consistent" {
			t.Fatal("actual Node finalize sources", checked, checkErr)
		}
		a.sourceMu.Lock()
		observed := 0
		for _, source := range a.requests {
			if source.Run != runID {
				continue
			}
			observed++
			owner, ok := owners[source.Task]
			if !ok || source.Engine != owner.EngineRun || source.Step != owner.Step || source.Output != owner.Output {
				t.Error("application request lost original task", source, owner)
			}
		}
		a.sourceMu.Unlock()
		if observed == 0 {
			t.Fatal("actual application received no original source")
		}
		t.Logf("normal_node run=%s sources=%v application_requests=%d physical_status=unavailable", runID, counts, observed)
	}
}

type finalizeContextApp struct {
	app.Application
	ctx context.Context
	req app.FinalizeRequest
}

func (a *finalizeContextApp) FinalizeBlock(ctx context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	a.ctx, a.req = ctx, req
	return app.FinalizeResponse{Hash: codec.BlockHash(req.Block.Header)}, nil
}

func TestFinalizeBridgePreservesOriginalContextAndSourceValue(t *testing.T) {
	key := testKey(0)
	_, b := testGenesis(t, key)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a := &finalizeContextApp{}
	d := &appDriver{a: a, ctx: ctx}
	s := app.FinalizeSource{Run: "original", Engine: 1, Step: 2, Output: 3, Task: 4}
	if err := d.FinalizeBlockWithSource(b, types.Round{}, s); err != nil {
		t.Fatal(err)
	}
	if a.ctx != ctx || a.req.Block != b || a.req.Source == nil || *a.req.Source != s {
		t.Fatal("original request changed")
	}
	s.Task++
	if a.req.Source.Task != 4 {
		t.Fatal("source borrowed caller's mutable value")
	}
	cancel()
	if a.ctx.Err() != context.Canceled {
		t.Fatal("bridge lost original cancellation")
	}
	if err := d.FinalizeBlock(b, types.Round{}); err != nil {
		t.Fatal(err)
	}
	if a.req.Source != nil {
		t.Fatal("ordinary caller acquired a source")
	}
}
