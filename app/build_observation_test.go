package app

import (
	"sync"
	"testing"

	"github.com/0xmhha/wbft/types"
)

func TestBuildObservationCopiesShareOneAssemblyAndCompletion(t *testing.T) {
	var phases []BuildPhase
	var statuses []BuildStatus
	var hashes []types.Hash
	o := NewBuildObservation(func(p BuildPhase, s BuildStatus, h types.Hash) {
		phases = append(phases, p)
		statuses = append(statuses, s)
		hashes = append(hashes, h)
	})
	req := BuildRequest{Observation: o}
	copyReq := req
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); copyReq.Observation.Started() }()
	}
	wg.Wait()
	hash := types.Hash{7}
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); req.Observation.Finished(BuildSubmitted, hash) }()
	}
	wg.Wait()
	o.Started()
	o.Finished(BuildFailed, types.Hash{})
	if len(phases) != 2 || phases[0] != BuildAssemblyStarted || phases[1] != BuildCompleted || statuses[1] != BuildSubmitted || hashes[1] != hash {
		t.Fatalf("duplicate/reordered observation: %v/%v/%v", phases, statuses, hashes)
	}
}

func TestBuildObservationCancellationDoesNotInventAssembly(t *testing.T) {
	var phases []BuildPhase
	o := NewBuildObservation(func(p BuildPhase, _ BuildStatus, _ types.Hash) { phases = append(phases, p) })
	o.Finished("unknown", types.Hash{})
	if len(phases) != 0 {
		t.Fatal("invalid status recorded")
	}
	o.Finished(BuildReplaced, types.Hash{})
	o.Started()
	if len(phases) != 1 || phases[0] != BuildCompleted {
		t.Fatal("replacement invented an assembly", phases)
	}
	var disabled *BuildObservation
	disabled.Started()
	disabled.Finished(BuildSubmitted, types.Hash{})
	if NewBuildObservation(nil) != nil {
		t.Fatal("disabled observer created")
	}
}
