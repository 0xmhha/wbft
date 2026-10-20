package node

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// heldImportApp delays one ordinary valid block without changing its bytes.
type heldImportApp struct {
	*testApp
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *heldImportApp) FinalizeBlock(ctx context.Context, req app.FinalizeRequest) (app.FinalizeResponse, error) {
	a.once.Do(func() { close(a.entered); <-a.release })
	return a.testApp.FinalizeBlock(ctx, req)
}

type importTimerEvents struct {
	buffer   syncBuffer
	watch    bool
	fired    bool
	observed chan struct{}
	once     sync.Once
}

func (s *importTimerEvents) Write(p []byte) (int, error) {
	n, err := s.buffer.Write(p)
	if err != nil {
		return n, err
	}
	var record struct {
		Kind  string `json:"kind"`
		Timer string `json:"timer"`
		Cause string `json:"cause"`
	}
	if err = json.Unmarshal(p, &record); err != nil {
		return n, err
	}
	if record.Kind == "TIMER_FIRE" && record.Timer == "round" {
		s.fired = true
	}
	if s.fired && (s.watch && record.Kind == "TIMER_ARM" && record.Timer == "round" || !s.watch && record.Kind == "ROUND_ENTER" && record.Cause == "timeout") {
		s.once.Do(func() { close(s.observed) })
	}
	return n, nil
}

func TestImportWatchdogLiveNodeDelayAndJournal(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "watchdog"}[watch], func(t *testing.T) {
			key := testKey(0)
			raw, genesis := testGenesis(t, key)
			a := &heldImportApp{testApp: newTestApp(raw, genesis), entered: make(chan struct{}), release: make(chan struct{})}
			events := &importTimerEvents{watch: watch, observed: make(chan struct{})}
			fs := fsys.NewMem()
			names := []string{}
			if watch {
				names = []string{"commit_watchdog", "advance_on_commit_failure"}
			}
			n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a.testApp, fs: fs, key: key, Events: events})
			if err != nil {
				t.Fatal(err)
			}
			a.cons = n.Consensus()
			if err = n.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(a.release) }); stop(t, n) })
			select {
			case <-a.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("ordinary import not started")
			}
			select {
			case <-events.observed:
			case <-time.After(10 * time.Second):
				t.Fatal("round timeout behavior not observed")
			}
			n.mu.Lock()
			runner := n.r
			n.mu.Unlock()
			snapshot := runner.Snapshot()
			// Event delivery can precede publication of the after-step snapshot.
			// Wait for the already observed legacy transition to become visible.
			if !watch {
				deadline := time.Now().Add(time.Second)
				for snapshot.View.Round.IsZero() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
					snapshot = runner.Snapshot()
				}
			}
			if watch && (snapshot.State != consensus.Committed || !snapshot.View.Round.IsZero()) {
				t.Fatal("slow import left decided round", snapshot)
			}
			if !watch && snapshot.View.Round.IsZero() {
				t.Fatal("legacy timeout changed")
			}
			release.Do(func() { close(a.release) })
			a.waitHead(t, 2, 10*time.Second)
			if err = n.Stop(); err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(fs, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			segments := 0
			for _, record := range records {
				if segment, ok := record.Body.(*journal.SegmentRec); ok {
					segments++
					if segment.Core.Improvements != uint64(n.coreImprovements) || string(segment.Core.ChainConfig) != string(raw) {
						t.Fatal("journal changed options or original chain configuration")
					}
				}
			}
			if segments == 0 {
				t.Fatal("journal metadata absent")
			}
		})
	}
}
