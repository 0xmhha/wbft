package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestWallOriginsStayIndependentAcrossRunsAndRestarts(t *testing.T) {
	keys := testValidators(t, 4)
	origins := []time.Time{time.Unix(1800000000, 605685000).UTC(), time.Unix(1900000000, 105685000).UTC()}
	type outcome struct {
		origin int
		result *Result
		err    error
	}
	results := make(chan outcome, 4)
	for i, origin := range origins {
		for repeat := 0; repeat < 2; repeat++ {
			go func(i int, origin time.Time) {
				nodes := []NodeSpec{DefaultNode(), DefaultNode(), DefaultNode(), DefaultNode()}
				nodes[1].ClockSkew = 125 * time.Millisecond
				sc := Scenario{Validators: keys, Nodes: nodes, Seed: 17, WallOrigin: origin, Until: Stop{Height: 5, Duration: 15 * time.Second}, Schedule: []NodeEvent{{Node: addrOf(keys[3]), At: 1100 * time.Millisecond, Action: ActionStop}, {Node: addrOf(keys[3]), At: 1700 * time.Millisecond, Action: ActionRestart}}}
				result, err := Run(context.Background(), sc, Output{})
				results <- outcome{i, result, err}
			}(i, origin)
		}
	}
	previous := map[int]*Result{}
	for range 4 {
		got := <-results
		if got.err != nil || got.result == nil {
			t.Fatalf("run failed: %v", got.err)
		}
		result := got.result
		if len(result.Violations) > 0 {
			t.Fatalf("violations: %v", result.Violations)
		}
		if result.Chain[0].Header.Time != uint64(origins[got.origin].Unix())-1 {
			t.Fatal("genesis used another run's clock")
		}
		restarts := 0
		for _, raw := range result.Events {
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
				var event struct {
					Node string `json:"node"`
					Kind string `json:"kind"`
					Wall string `json:"t_wall"`
					Mono int64  `json:"t_mono_ns"`
				}
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				wall, err := time.Parse(time.RFC3339Nano, event.Wall)
				if err != nil {
					t.Fatal(err)
				}
				skew := time.Duration(0)
				if event.Node == hexAddr(addrOf(keys[1])) {
					skew = 125 * time.Millisecond
				}
				want := origins[got.origin].Add(time.Duration(event.Mono) + skew)
				if !wall.Equal(want) {
					t.Fatalf("clock %s want %s", wall, want)
				}
				if event.Kind == "NODE_START" && event.Node == hexAddr(addrOf(keys[3])) {
					restarts++
				}
			}
		}
		if restarts != 2 {
			t.Fatalf("restart not exercised: %d", restarts)
		}
		if first := previous[got.origin]; first != nil {
			if !reflect.DeepEqual(first, result) {
				t.Fatal("same origin and seed changed outputs")
			}
		} else {
			previous[got.origin] = result
		}
	}
	if reflect.DeepEqual(previous[0].Events, previous[1].Events) {
		t.Fatal("different origins produced identical wall clocks")
	}
}

func TestDefaultWallOriginMatchesExplicitEpoch(t *testing.T) {
	sc := Scenario{Validators: testValidators(t, 4), Seed: 7, Until: Stop{Height: 3, Duration: time.Minute}}
	a, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	sc.WallOrigin = Epoch.In(time.FixedZone("offset", 3600))
	b, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("default origin changed existing outputs")
	}
}

func TestWallOriginClockDomain(t *testing.T) {
	keys := testValidators(t, 4)
	cases := []struct {
		origin time.Time
		skew   time.Duration
	}{
		{time.Unix(0, 1), 0}, {time.Unix(-1, 0), 0}, {time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{time.Unix(0, math.MaxInt64), 0}, {time.Unix(1, 0), -2 * time.Second},
		{time.Unix(0, math.MaxInt64-int64(time.Minute)), 2 * time.Minute},
	}
	for _, c := range cases {
		sc := Scenario{Validators: keys, WallOrigin: c.origin, Nodes: []NodeSpec{{ClockSkew: c.skew}}, Until: Stop{Height: 2, Duration: time.Minute}}
		if _, err := Run(context.Background(), sc, Output{}); !errors.Is(err, ErrScenario) {
			t.Fatalf("invalid clock accepted: %s skew %s: %v", c.origin, c.skew, err)
		}
	}
}

func TestWallOriginClockSnapshot(t *testing.T) {
	origin := time.Unix(1800000000, 605685000).UTC()
	sc := Scenario{Validators: testValidators(t, 1), WallOrigin: origin, Until: Stop{Height: 2, Duration: time.Minute}}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.WallOrigin = origin.Add(time.Hour)
	s.ctx = context.Background()
	n := s.nodes[0]
	n.start()
	defer n.stop()
	if got := n.clock.Now(); !got.Equal(origin) {
		t.Fatalf("origin changed after initialization: %s", got)
	}
}
