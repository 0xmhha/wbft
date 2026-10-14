package node

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestBuildCompletionKeepsOriginalWriterAcrossReplacement(t *testing.T) {
	var old, newRun bytes.Buffer
	a := event.NewWriter(&old, types.Address{1}, "original-run")
	b := event.NewWriter(&newRun, types.Address{1}, "new-run")
	n := &Node{ev: a, clock: runner.SystemClock()}
	emit := n.buildEventEmitter()
	n.ev = b
	emit(event.Record{Kind: event.BuildFinished, Fields: map[string]any{"build_id": "build-1", "number": "1", "status": "replaced"}})
	if newRun.Len() != 0 || old.Len() == 0 {
		t.Fatal("completion moved to another writer run")
	}
	var row struct {
		Run string `json:"run"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(old.Bytes()), &row); err != nil || row.Run != "original-run" {
		t.Fatal(row, err)
	}
}
func TestBuildCallbacksDoNotRaceNodeWriterReplacement(t *testing.T) {
	var old, newRun bytes.Buffer
	a := event.NewWriter(&old, types.Address{1}, "original-run")
	b := event.NewWriter(&newRun, types.Address{1}, "new-run")
	n := &Node{ev: a, clock: runner.SystemClock()}
	emit := n.buildEventEmitter()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 64 {
			emit(event.Record{Kind: event.BuildFinished, Fields: map[string]any{"build_id": "build-1", "number": "1", "status": "replaced"}})
		}
	}()
	for range 64 {
		n.ev = b
		n.ev = a
	}
	wg.Wait()
	if newRun.Len() != 0 || bytes.Count(old.Bytes(), []byte("\n")) != 64 {
		t.Fatal("callback observed mutable writer ownership")
	}
}
