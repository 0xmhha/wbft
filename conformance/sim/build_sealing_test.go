package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/taskqueue"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/event/schema"
	"github.com/0xmhha/wbft/types"
)

func sealingSpec() NodeSpec {
	s := DefaultNode()
	s.BuildQueuePolicy = BuildQueueSealing
	s.Sealing = &SealingProfile{Selection: SealingSeeded, ResultCapacity: 10, CallDelay: []time.Duration{0, time.Millisecond}, PostDelay: []time.Duration{0, 2 * time.Millisecond}}
	s.BuildDelay = []time.Duration{7 * time.Millisecond}
	return s
}

func TestSealingProfileDeterministicChainAndEvidence(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		nodes := []NodeSpec{sealingSpec(), sealingSpec(), sealingSpec(), sealingSpec()}
		if mixed {
			nodes[1], nodes[2], nodes[3] = serialSpec(), DefaultNode(), DefaultNode()
		}
		sc := Scenario{Validators: testValidators(t, 4), Nodes: nodes, Until: Stop{Height: 8, Duration: time.Minute}}
		first, err := Run(context.Background(), sc, Output{})
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Violations) > 0 {
			t.Fatal(mixed, first.Violations)
		}
		second, err := Run(context.Background(), sc, Output{})
		if err != nil || len(second.Chain) != len(first.Chain) || len(first.Chain) < 8 {
			t.Fatal(mixed, err, len(first.Chain), len(second.Chain))
		}
		for i, block := range first.Chain {
			if codec.BlockHash(block.Header) != codec.BlockHash(second.Chain[i].Header) {
				t.Fatal("seed changed chain")
			}
		}
		scValidator, err := schema.Load()
		if err != nil {
			t.Fatal(err)
		}
		stages, declared := 0, 0
		paths := map[string]int{}
		for name, data := range first.Events {
			if !bytes.Equal(data, second.Events[name]) {
				t.Fatal("seed changed event trace", name)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if err := scValidator.Validate([]byte(line)); err != nil {
					t.Fatal(err, line)
				}
				var row struct {
					Kind  event.Kind     `json:"kind"`
					Model map[string]any `json:"application_model"`
					Path  string         `json:"path"`
				}
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Fatal(err)
				}
				if row.Kind == sealingStage {
					stages++
				}
				if row.Kind == event.NewHead {
					paths[row.Path]++
				}
				if row.Kind == event.NodeStart && row.Model["build_queue"] == BuildQueueSealing {
					declared++
				}
			}
		}
		want := 4
		if mixed {
			want = 1
		}
		if stages == 0 || declared != want {
			t.Fatal("missing or implicit profile", stages, declared, want)
		}
		if !mixed && (paths[event.PathImported] == 0 || paths[event.PathSealedLocally] == 0) {
			t.Fatal("forwarded commits and local sealing results lost distinct import paths", paths)
		}
	}
}

func TestSealingScheduledRestartWaitsForOldWorker(t *testing.T) {
	keys := testValidators(t, 1)
	spec := sealingSpec()
	spec.BuildDelay = []time.Duration{4 * time.Second}
	sc := Scenario{Validators: keys, Nodes: []NodeSpec{spec}, Until: Stop{Duration: 20 * time.Second}, Schedule: []NodeEvent{
		{Node: addrOf(keys[0]), At: 2 * time.Second, Action: ActionStop},
		{Node: addrOf(keys[0]), At: 2100 * time.Millisecond, Action: ActionRestart},
	}}
	result, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) > 0 {
		t.Fatal(result.Violations)
	}
	starts := 0
	for _, raw := range result.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var row struct {
				Kind event.Kind `json:"kind"`
			}
			if json.Unmarshal([]byte(line), &row) == nil && row.Kind == event.NodeStart {
				starts++
			}
		}
	}
	if starts != 2 || len(result.Chain) < 2 {
		t.Fatal("scheduled restart did not follow worker return", starts, len(result.Chain))
	}
}

func sealingAssembly(t *testing.T) (*simulation, *node, *sealingBuilder, string) {
	t.Helper()
	spec := sealingSpec()
	spec.BuildDelay = []time.Duration{10 * time.Second}
	s, err := newSimulation(Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{spec}, Until: Stop{Duration: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	n := s.nodes[0]
	n.start()
	s.pumpAll()
	for n.app.sealing.work.Phase() != taskqueue.BuildingWork {
		at, ok := s.l.nextTime()
		if !ok || at > 5*time.Second {
			t.Fatal("assembly absent")
		}
		s.l.runAt(at)
		s.pumpAll()
	}
	return s, n, n.app.sealing, n.app.sealing.work.ActiveID()
}

func TestSealingStopKeepsAssemblyAndDefersRestart(t *testing.T) {
	s, n, b, id := sealingAssembly(t)
	oldRun, inc := n.runID(), n.inc
	n.stop()
	n.start()
	if n.alive || n.inc != inc || b.work.ActiveID() != id || b.closed {
		t.Fatal("stop invented assembly return or overlapped worker")
	}
	for !b.closed {
		at, ok := s.l.nextTime()
		if !ok || at > 15*time.Second {
			t.Fatal("close did not follow return", b.work.Phase())
		}
		s.l.runAt(at)
		s.pumpAll()
	}
	if !n.alive || n.inc != inc+1 || n.app.sealing == b {
		t.Fatal("restart absent")
	}
	data := n.eventFiles["events-"+oldRun+".jsonl"].String()
	if !strings.Contains(data, `"stage":"returned"`) || !strings.Contains(data, `"work_id":"`+id+`"`) {
		t.Fatal("old run lost executor return")
	}
	n.crash()
	if len(s.viol) > 0 {
		t.Fatal(s.viol)
	}
}

func TestSealingCrashDoesNotInventAssemblyReturn(t *testing.T) {
	s, n, b, _ := sealingAssembly(t)
	oldRun := n.runID()
	n.crash()
	s.l.c.AdvanceTo(20 * time.Second)
	s.pumpAll()
	if !b.closed || strings.Contains(n.eventFiles["events-"+oldRun+".jsonl"].String(), `"stage":"returned"`) {
		t.Fatal("crash fabricated executor return")
	}
}

func TestSealingIgnoresRequestDoneAndUsesSelectedHead(t *testing.T) {
	s, n, b, _ := sealingAssembly(t)
	defer n.crash()
	done := make(chan struct{})
	close(done)
	n.app.ReadyToBuild(consensus.RequestBuild{Height: types.HeightFromUint64(999), Round: types.RoundFromUint64(0)}, 0, done)
	id := b.order[len(b.order)-1]
	// Keep the initial assembly occupied. The callback can rendezvous with
	// the producer but its request must wait for the serial assembler.
	for b.work.OfferedID() != id {
		at, ok := s.l.nextTime()
		if !ok || at > time.Second {
			t.Fatal("callback was cancelled by request Done")
		}
		s.l.runAt(at)
		s.pumpAll()
	}
	for b.jobs[id].block == nil {
		at, ok := s.l.nextTime()
		if !ok || at > 15*time.Second {
			t.Fatal("serial assembler never accepted callback")
		}
		s.l.runAt(at)
		s.pumpAll()
	}
	job := b.jobs[id]
	if job.req.Height.CmpUint64(999) != 0 || job.block.Header.Number.CmpUint64(1) != 0 || job.block.Header.ParentHash != codec.BlockHash(s.genesis.Header) {
		t.Fatal("request height replaced the actual selected chain head")
	}
	if len(s.viol) > 0 {
		t.Fatal(s.viol)
	}
}

func TestSealingHeadBackpressureSurvivesStopUntilUnsubscribe(t *testing.T) {
	_, n, b, _ := sealingAssembly(t)
	defer n.crash()
	b.localPublish = true
	for i := 0; i < sealingHeadCapacity+2; i++ {
		b.headNotice(n.app.chain.head.Header)
	}
	b.localPublish = false
	if len(b.heads) != 10 || len(b.headOffers) != 2 || b.importHeadPending != 2 {
		t.Fatal("head channel did not block publishers")
	}
	n.stop()
	if b.importHeadPending != 2 {
		t.Fatal("core stop released a blocked chain write")
	}
	// The worker assembly loop owns this subscription. Closing it releases
	// blocked publishers independently of the stopped consensus runner.
	b.unsubscribeHeads()
	if b.importHeadPending != 0 || len(b.headOffers) != 0 {
		t.Fatal("unsubscribe retained publishers")
	}
}

func TestSealingProfileRejectsUndeclaredAndUnboundedBehavior(t *testing.T) {
	changes := []func(*NodeSpec){
		func(s *NodeSpec) { s.Sealing = nil },
		func(s *NodeSpec) { s.Sealing.Selection = "" },
		func(s *NodeSpec) { s.Sealing.Selection = "timestamp_priority" },
		func(s *NodeSpec) { s.Sealing.ResultCapacity = 0 },
		func(s *NodeSpec) { s.Sealing.ResultCapacity = 1025 },
		func(s *NodeSpec) { s.BuildDoneResult = BuildDoneFails },
		func(s *NodeSpec) { s.Sealing.CallDelay = []time.Duration{-1} },
		func(s *NodeSpec) { s.Sealing.PostDelay = []time.Duration{time.Hour} },
		func(s *NodeSpec) { s.BuildDelay = make([]time.Duration, 257) },
		func(s *NodeSpec) { s.ImportDelay = make([]time.Duration, 257) },
		func(s *NodeSpec) { s.BuildQueuePolicy = "" },
		func(s *NodeSpec) { s.BuildQueuePolicy = BuildQueueSerial; s.BuildDoneResult = BuildDoneFails },
	}
	keys := testValidators(t, 1)
	for i, change := range changes {
		spec := sealingSpec()
		change(&spec)
		if _, err := newSimulation(Scenario{Validators: keys, Nodes: []NodeSpec{spec}, Until: Stop{Duration: time.Minute}}); err == nil {
			t.Fatal("invalid profile became default", i)
		}
	}
}

func TestSealingBlockedCommitDefersCoreStopAndRestart(t *testing.T) {
	_, n, b, id := sealingAssembly(t)
	defer n.crash()
	block := b.jobs[id].block
	if err := b.seals.Begin(taskqueue.SealRequest{ID: id, Hash: [32]byte(codec.BlockHash(block.Header))}); err != nil {
		t.Fatal(err)
	}
	b.sealEffects(b.seals.Acquire(id))
	completed := 0
	complete := func(err error) {
		if err != nil {
			t.Error(err)
		}
		completed++
	}
	b.commit(block, complete)
	b.commit(block, complete)
	if completed != 1 || !b.seals.CommitBlocked() {
		t.Fatal("full commit channel did not retain core call", completed)
	}
	inc := n.inc
	n.stop()
	n.start()
	if !n.alive || !n.down || n.inc != inc || !b.stopRequested || !b.restart {
		t.Fatal("blocked core was stopped/restarted before Commit returned")
	}
	// The asynchronous sealer is the actor that can make channel space. Stop
	// itself cannot consume or cancel the pending core call.
	b.sealEffects(b.seals.ChooseCommit(id))
	b.resultDone = true
	for i := 0; n.alive && i < 1000; i++ {
		if !b.pump() {
			break
		}
	}
	if n.alive || completed != 2 || b.seals.CommitBlocked() || !b.closing || n.inc != inc {
		t.Fatal("stop did not wait for the actual channel handoff", completed)
	}
}
