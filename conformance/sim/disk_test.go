package sim

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A write-ahead log cut at any byte or with a damaged record is repaired at
// the restart: the node replays what is readable and joins again (the
// agreement, signing and progress checks of Run hold). A sign state file
// that was cut refuses the start.
func TestDiskFaults(t *testing.T) {
	n := seedCount(t, 6)
	for _, kind := range []string{DiskTruncateWAL, DiskCorruptWAL, DiskPartialSignState} {
		damaged, corrupted := 0, 0
		for seed := int64(0); seed < int64(n); seed++ {
			r := seedRand(seed, 99)
			sc := base("disk", seed, testValidators(t, 4), 4, 8)
			a := addrOf(sc.Validators[r.IntN(4)])
			at := time.Duration(1+r.IntN(4))*time.Second + ms(r, 5, 60)
			sc.Schedule = []NodeEvent{{At: at, Node: a, Action: ActionCrash}, {At: at + ms(r, 200, 1500), Node: a, Action: ActionRestart}}
			sc.Disk = []DiskFault{{At: at + time.Millisecond, Node: a, Kind: kind}}
			res, err := Run(context.Background(), sc, Output{})
			if err != nil {
				t.Fatal(err)
			}
			damaged += res.Damaged
			for _, v := range res.Violations {
				if kind == DiskPartialSignState && v.Kind == "start" && strings.Contains(v.Detail, "sign state") && v.Node == a {
					continue
				}
				t.Fatalf("%s seed %d: %v", kind, seed, v)
			}
			if kind == DiskPartialSignState && res.Damaged > 0 {
				refused := false
				for _, v := range res.Violations {
					refused = refused || v.Kind == "start"
				}
				if !refused {
					t.Fatalf("seed %d: a damaged sign state did not refuse the start", seed)
				}
			}
			for name, data := range res.Events {
				if strings.Contains(string(data), `"corrupted":1`) || strings.Contains(string(data), `"corrupted":2`) {
					corrupted++
					_ = name
				}
			}
		}
		if damaged == 0 {
			t.Fatalf("%s: no fault applied", kind)
		}
		t.Logf("%s: %d seeds, %d faults applied, %d starts found moved-aside segments", kind, n, damaged, corrupted)
	}
}
