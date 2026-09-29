package sim

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
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

// A node that restarts without its sign state and write-ahead log and with
// the takeover guard sets the sign floor at head + 1: it signs nothing at
// that height (sign_floor_skip) and joins from the next one.
func TestTakeoverGuard(t *testing.T) {
	for seed := int64(0); seed < int64(seedCount(t, 4)); seed++ {
		r := seedRand(seed, 98)
		sc := base("takeover", seed, testValidators(t, 4), 4, 8)
		i := r.IntN(4)
		a := addrOf(sc.Validators[i])
		for k := 0; k < 4; k++ {
			spec := DefaultNode()
			spec.TakeoverGuard = k == i
			sc.Nodes = append(sc.Nodes, spec)
		}
		at := time.Duration(1+r.IntN(4))*time.Second + ms(r, 5, 60)
		sc.Schedule = []NodeEvent{{At: at, Node: a, Action: ActionCrash}, {At: at + ms(r, 200, 800), Node: a, Action: ActionRestart}}
		sc.Disk = []DiskFault{{At: at + time.Millisecond, Node: a, Kind: DiskLoseState}}
		res, err := Run(context.Background(), sc, Output{})
		if err != nil || len(res.Violations) > 0 {
			t.Fatal(err, res.Violations)
		}
		floor, skip := false, false
		for _, data := range res.Events {
			floor = floor || strings.Contains(string(data), `"status":"set"`)
			skip = skip || strings.Contains(string(data), `"what":"sign_floor_skip"`)
		}
		if !floor {
			t.Fatalf("seed %d: no sign floor set", seed)
		}
		t.Logf("seed %d: floor set, skip reported %v, heads %v", seed, skip, res.Heads)
	}
}

// With small write-ahead log segments the log rotates within a height and
// old segments are removed as heights end; replays after crashes still
// restore the state.
func TestSmallWALSegments(t *testing.T) {
	replays, maxSegs := 0, 0
	var lastIndex uint64
	for seed := int64(0); seed < int64(seedCount(t, 6)); seed++ {
		sc := restarts(seed, testValidators(t, 4))
		sc.Until.Height = 12
		for k := 0; k < 4; k++ {
			spec := DefaultNode()
			spec.WALSegmentBytes = 4 << 10
			sc.Nodes = append(sc.Nodes, spec)
		}
		s, err := newSimulation(sc)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		res := s.result()
		if len(res.Violations) > 0 {
			t.Fatal(res.Violations)
		}
		for _, r := range res.Replays {
			if r.Replayed {
				replays++
			}
		}
		for _, n := range s.nodes {
			segs, _ := wal.Segments(n.fs, walDir)
			maxSegs = max(maxSegs, len(segs))
			if len(segs) > 0 {
				lastIndex = max(lastIndex, segs[len(segs)-1].Index)
			}
		}
	}
	if replays == 0 {
		t.Fatal("no replay")
	}
	// Twelve heights write many more segments than a node keeps.
	if lastIndex < 20 || maxSegs > 12 {
		t.Fatalf("segments: highest index %d, most kept %d", lastIndex, maxSegs)
	}
	t.Logf("%d replays; highest segment index %d, at most %d segments kept", replays, lastIndex, maxSegs)
}
