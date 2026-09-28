package sim

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// seedCount is the number of seeds per scenario: WBFT_SIM_SEEDS, or a
// short run by default (the full run uses 10000).
func seedCount(t *testing.T, short int) int {
	if s := os.Getenv("WBFT_SIM_SEEDS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if testing.Short() {
		return 2
	}
	return short
}

type runStat struct {
	runs, crashes, replays, evidence int
	wall                             time.Duration
	maxRound                         uint64
}

// runSeeds runs the template for seeds [0, n) in parallel and fails on the
// first violation.
func runSeeds(t *testing.T, tpl Template, n int) runStat {
	keys := testValidators(t, 7)
	par := runtime.GOMAXPROCS(0)
	var mu sync.Mutex
	var st runStat
	var failed []string
	next := int64(0)
	var wg sync.WaitGroup
	for w := 0; w < par; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				seed := next
				next++
				stop := seed >= int64(n) || len(failed) > 0
				mu.Unlock()
				if stop {
					return
				}
				start := time.Now()
				sc := tpl.Make(seed, keys)
				res, err := Run(context.Background(), sc, Output{})
				d := time.Since(start)
				mu.Lock()
				st.runs++
				st.wall += d
				if err != nil {
					failed = append(failed, fmt.Sprintf("seed %d: %v", seed, err))
				} else {
					st.crashes += res.Crashes
					st.evidence += res.Evidence
					for _, r := range res.Replays {
						if r.Replayed {
							st.replays++
						}
					}
					for _, r := range res.Rounds {
						st.maxRound = max(st.maxRound, r)
					}
					for _, v := range res.Violations {
						failed = append(failed, fmt.Sprintf("seed %d: %s", seed, v))
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		t.Fatalf("%s: %d violations, first: %s", tpl.Name, len(failed), failed[0])
	}
	return st
}

// TestBundle runs every scenario of the bundle with reference behaviour
// and the two restart-safety rules and checks agreement, no double
// signing, progress and the header rules.
func TestBundle(t *testing.T) {
	n := seedCount(t, 8)
	for _, tpl := range Bundle() {
		tpl := tpl
		t.Run(tpl.Name, func(t *testing.T) {
			start := time.Now()
			st := runSeeds(t, tpl, n)
			t.Logf("%s: %d seeds in %s (cpu %s), crashes %d, replays %d, evidence %d, max round %d",
				tpl.Name, st.runs, time.Since(start).Round(time.Millisecond), st.wall.Round(time.Millisecond), st.crashes, st.replays, st.evidence, st.maxRound)
		})
	}
}
