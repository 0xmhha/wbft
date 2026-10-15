package sim

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func timingValue(v uint64) *uint64 { return &v }

func TestResolveTimingExplicitValuesAndImmutableSnapshots(t *testing.T) {
	base := Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: 1, MaxRequestTimeoutSeconds: timingValue(3)}
	input := &TimingParams{RequestTimeoutSeconds: timingValue(5), MaxRequestTimeoutSeconds: timingValue(0)}
	out, err := ResolveTiming(base, input, time.Minute)
	if err != nil || out.RequestTimeoutSeconds != 5 || out.BlockPeriodSeconds != 1 || out.EpochLength != 4 || out.ProposerPolicy != 1 || out.MaxRequestTimeoutSeconds == nil || *out.MaxRequestTimeoutSeconds != 0 {
		t.Fatal(out, err)
	}
	*out.MaxRequestTimeoutSeconds = 9
	if *input.MaxRequestTimeoutSeconds != 0 || *base.MaxRequestTimeoutSeconds != 3 {
		t.Fatal("timing values alias caller state")
	}
	for _, bad := range []*TimingParams{{RequestTimeoutSeconds: timingValue(0)}, {BlockPeriodSeconds: timingValue(0)}, {MaxRequestTimeoutSeconds: timingValue(math.MaxUint64)}, {RequestTimeoutSeconds: timingValue(uint64((time.Duration(math.MaxInt64)-time.Minute)/time.Second) + 1)}} {
		if _, err := ResolveTiming(base, bad, time.Minute); err == nil {
			t.Fatal("unrepresentable explicit timing accepted", bad)
		}
	}
	sc := timingCompatibilityScenario(t, 2)
	sc.Params = base
	sc.Nodes[1].Timing = input
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	*input.RequestTimeoutSeconds = 100
	*input.MaxRequestTimeoutSeconds = 100
	*base.MaxRequestTimeoutSeconds = 100
	p := s.nodes[1].cfg.ConfigAt(types.HeightFromUint64(1))
	if p.RequestTimeoutMs != 5000 || p.MaxRequestTimeoutSeconds != 0 || *s.nodes[1].spec.Timing.RequestTimeoutSeconds != 5 || *s.sc.Params.MaxRequestTimeoutSeconds != 3 {
		t.Fatal("startup configuration was not snapshotted", p)
	}
	sc.Nodes = append(sc.Nodes, NodeSpec{Timing: &TimingParams{BlockPeriodSeconds: timingValue(2)}})
	if _, err := newSimulation(sc); err == nil {
		t.Fatal("override for nonexistent node accepted")
	}
}

func TestIdentityAndAllNodeTimingMatchSharedConfiguration(t *testing.T) {
	base := timingCompatibilityScenario(t, 7)
	want, err := Run(context.Background(), base, Output{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range base.Nodes {
		base.Nodes[i].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(2), BlockPeriodSeconds: timingValue(1)}
	}
	got, err := Run(context.Background(), base, Output{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("identity override changed events, journals or outcomes", err)
	}
	shared := timingCompatibilityScenario(t, 2)
	shared.Schedule = nil
	shared.Until.Duration = time.Minute
	shared.Params.RequestTimeoutSeconds = 10
	shared.Params.BlockPeriodSeconds = 4
	want, err = Run(context.Background(), shared, Output{})
	if err != nil || len(want.Violations) != 0 {
		t.Fatal(err, want.Violations)
	}
	perNode := timingCompatibilityScenario(t, 2)
	perNode.Schedule = nil
	perNode.Until.Duration = time.Minute
	for i := range perNode.Nodes {
		perNode.Nodes[i].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(10), BlockPeriodSeconds: timingValue(4)}
	}
	got, err = Run(context.Background(), perNode, Output{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("all-node overrides differ from shared timing", err)
	}
	for i := 1; i < len(got.Chain); i++ {
		if got.Chain[i].Header.Time-got.Chain[i-1].Header.Time < 4 {
			t.Fatal("fake application ignored block period")
		}
	}
}

func TestTimingVerificationCacheCannotCrossNodeConfigurations(t *testing.T) {
	sc := timingCompatibilityScenario(t, 7)
	sc.Schedule = nil
	sc.Until.Height = 1
	sc.Params.RequestTimeoutSeconds = 10
	result, err := Run(context.Background(), sc, Output{})
	if err != nil || len(result.Chain) < 2 {
		t.Fatal(err)
	}
	sc.Nodes[1].Timing = &TimingParams{BlockPeriodSeconds: timingValue(4)}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range s.nodes {
		node.clock = &nodeClock{l: &s.l, origin: s.sc.WallOrigin, live: func() bool { return true }}
	}
	block := result.Chain[1]
	if err := s.nodes[0].app.importBlock(block, "imported"); err != nil {
		t.Fatal("weak-period node did not prime verification cache", err)
	}
	if err := s.nodes[1].app.importBlock(block, "imported"); err == nil || s.nodes[1].head() != 0 {
		t.Fatal("one node's verified header bypassed another node's block period")
	}
	if len(s.verified) != 1 {
		t.Fatal("failed verification entered cache")
	}
}

func TestPerNodeTimersAndJournalConfigurationsSurviveRestart(t *testing.T) {
	sc := timingCompatibilityScenario(t, 4)
	sc.Until = Stop{Duration: 70 * time.Second}
	sc.NoProgress = true
	sc.DefaultLink.Delay = []time.Duration{4 * time.Second}
	sc.Params.MaxRequestTimeoutSeconds = timingValue(3)
	sc.Nodes[1].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(5), MaxRequestTimeoutSeconds: timingValue(17)}
	sc.Nodes[2].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(7), MaxRequestTimeoutSeconds: timingValue(0)}
	sc.Nodes[3].Timing = &TimingParams{RequestTimeoutSeconds: timingValue(11)}
	sc.Schedule = []NodeEvent{{At: 31 * time.Second, Node: addrOf(sc.Validators[1]), Action: ActionStop}, {At: 33 * time.Second, Node: addrOf(sc.Validators[1]), Action: ActionRestart}}
	root := t.TempDir()
	result, err := Run(context.Background(), sc, Output{JournalDir: root})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	first := map[int]int64{}
	later := map[int]map[int64]bool{}
	restarted := false
	restartTimer := false
	for _, data := range result.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var event struct {
				Kind, Node, Timer string
				Duration          int64  `json:"duration_ms"`
				Mono              int64  `json:"t_mono_ns"`
				Deadline          *int64 `json:"deadline_mono_ns"`
				View              *struct {
					Round string `json:"round"`
				} `json:"view"`
			}
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			node := -1
			for i, key := range sc.Validators {
				if strings.EqualFold(event.Node, addrOf(key).Hex()) {
					node = i
				}
			}
			if node == 1 && event.Kind == "NODE_START" && event.Mono >= int64(33*time.Second) {
				restarted = true
			}
			if event.Kind != "TIMER_ARM" || event.Timer != "round" || event.View == nil || node < 0 {
				continue
			}
			round, err := strconv.ParseUint(event.View.Round, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if event.Deadline != nil && *event.Deadline-event.Mono != event.Duration*int64(time.Millisecond) {
				t.Fatal("actual timer deadline differs from its armed duration", event)
			}
			if node == 1 && event.Mono >= int64(33*time.Second) && (event.Duration == 5000 || event.Duration == 10000 || event.Duration == 17000) {
				restartTimer = true
			}
			if round == 0 {
				if _, found := first[node]; !found {
					first[node] = event.Duration
				}
			} else {
				if later[node] == nil {
					later[node] = map[int64]bool{}
				}
				later[node][event.Duration] = true
			}
		}
	}
	t.Log("round zero", first, "later", later)
	if !reflect.DeepEqual(first, map[int]int64{0: 2000, 1: 5000, 2: 7000, 3: 11000}) || !restarted || !restartTimer {
		t.Fatal("runner ignored per-node timing or restart", first, restarted, restartTimer)
	}
	if !later[0][3000] || !later[1][10000] || !later[2][14000] || !later[3][3000] {
		t.Fatal("actual round timers ignored cap or explicit no-cap", later)
	}
	for i, key := range sc.Validators {
		dir := filepath.Join(root, strings.TrimPrefix(strings.ToLower(addrOf(key).Hex()), "0x"))
		if _, err := os.Stat(dir); err != nil {
			t.Fatal(err)
		}
		records, err := journal.ReadAll(nil, dir)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, record := range records {
			segment, ok := record.Body.(*journal.SegmentRec)
			if !ok {
				continue
			}
			seen[segment.Run] = true
			cfg, err := types.ParseChainConfig(segment.Core.ChainConfig)
			if err != nil {
				t.Fatal(err)
			}
			params := cfg.ConfigAt(types.HeightFromUint64(1))
			want := []uint64{2000, 5000, 7000, 11000}[i]
			cap := []uint64{3, 17, 0, 3}[i]
			if params.RequestTimeoutMs != want || params.MaxRequestTimeoutSeconds != cap {
				t.Fatal("journal differs from node configuration", i, params)
			}
		}
		if i == 1 && len(seen) < 2 {
			t.Fatal("restart journal configuration not retained")
		}
	}
}
