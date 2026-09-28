//go:build wbft_faults

package sim

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/faultpoint"
)

// TestCrashAtFaultPoints crashes a node at every fault point (the k-th
// time it passes it, for several k), restarts it and checks the verdicts
// of the crash tests: no conflicting signature after a restart, the lock
// and the prepared certificate restored when an own message was logged
// before the crash, no replay that differs from the original run, the
// decided block finalized again when the crash followed its commit
// request, and agreement and progress.
func TestCrashAtFaultPoints(t *testing.T) {
	if !faultpoint.Enabled {
		t.Skip("needs the build tag wbft_faults")
	}
	hits := seedCount(t, 10)
	keys := testValidators(t, 4)
	type job struct {
		point string
		hit   int
		seed  int64
	}
	var jobs []job
	for _, p := range faultpoint.All {
		for k := 0; k < hits; k++ {
			for seed := int64(0); seed < 2; seed++ {
				jobs = append(jobs, job{p, k, seed})
			}
		}
	}
	type stat struct{ crashes, locks, refinal, replays int }
	stats := map[string]*stat{}
	for _, p := range faultpoint.All {
		stats[p] = &stat{}
	}
	var mu sync.Mutex
	var failed []string
	next := 0
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if next >= len(jobs) || len(failed) > 0 {
					mu.Unlock()
					return
				}
				j := jobs[next]
				next++
				mu.Unlock()
				r := seedRand(j.seed*1000+int64(j.hit), 77)
				sc := base("fault", j.seed, keys, 4, 8)
				node := addrOf(sc.Validators[(j.hit+int(j.seed))%4])
				sc.Faults = []Fault{{Node: node, Point: j.point, Hit: j.hit, RestartAfter: ms(r, 10, 1500)}}
				res, err := Run(context.Background(), sc, Output{})
				mu.Lock()
				st := stats[j.point]
				if err != nil {
					failed = append(failed, err.Error())
				} else {
					st.crashes += res.Crashes
					st.locks += res.LockChecks
					st.refinal += res.Refinalize
					for _, rp := range res.Replays {
						if rp.Replayed {
							st.replays++
						}
					}
					for _, v := range res.Violations {
						failed = append(failed, fmt.Sprintf("%s hit %d seed %d: %s", j.point, j.hit, j.seed, v))
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		t.Fatalf("%d failures, first: %s", len(failed), failed[0])
	}
	for _, p := range faultpoint.All {
		st := stats[p]
		t.Logf("%-22s crashes %3d  locks compared %3d  finalized again %3d  replays %3d", p, st.crashes, st.locks, st.refinal, st.replays)
		if st.crashes == 0 {
			t.Errorf("%s: never reached", p)
		}
	}
	if stats[faultpoint.CommitAfter].refinal == 0 {
		t.Error("no block was finalized again after a crash that followed its commit request")
	}
	if stats[faultpoint.WALAfterOwnMsg].locks == 0 {
		t.Error("no lock was compared after a crash that followed an own message")
	}
	t.Logf("%d runs in %s", len(jobs), time.Since(start).Round(time.Millisecond))
}
