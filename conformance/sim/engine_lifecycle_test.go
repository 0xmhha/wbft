package sim

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/taskqueue"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func advanceEngineTest(t *testing.T, s *simulation, until time.Duration, done func() bool) {
	t.Helper()
	for steps := 0; steps < 100000; steps++ {
		s.pumpAll()
		if done() {
			return
		}
		at, ok := s.l.nextTime()
		if !ok || at > until {
			for _, n := range s.nodes {
				t.Log("deadline node", n.i, "head", n.head(), "running", n.r.Running(), "view", n.r.Snapshot().View)
			}
			t.Fatal("condition not reached before deadline", s.l.c.Mono(), s.viol)
		}
		s.l.runAt(at)
	}
	t.Fatal("condition did not settle")
}

func TestEnginePauseKeepsImportsTransportAndIncarnation(t *testing.T) {
	s, err := newSimulation(Scenario{Validators: testValidators(t, 4), Until: Stop{Duration: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	s.l.after(syncInterval, s.syncTick)
	for _, n := range s.nodes {
		n.start()
		defer n.stop()
	}
	s.pumpAll()
	n := s.nodes[3]
	r, app, signer, log, journal, transport, clock := n.r, n.app, n.signer, n.log, n.jw, n.tr, n.clock
	inc, generation, head := n.inc, r.EngineRun(), n.head()
	n.requestEngineAction(ActionEngineStop)
	s.pumpAll()
	if !n.alive || n.down || r.Running() || n.inc != inc || n.app != app || n.r != r || n.signer != signer || n.log != log || n.jw != journal || n.tr != transport || n.clock != clock {
		t.Fatal("consensus pause changed the node incarnation")
	}
	advanceEngineTest(t, s, 20*time.Second, func() bool { return n.head() >= head+3 })
	if r.Running() || n.app.gen != 0 || len(n.eventFiles) != 1 {
		t.Fatal("application or event stream restarted while consensus paused")
	}
	n.requestEngineAction(ActionEngineStart)
	s.pumpAll()
	if !r.Running() || r.EngineRun() != generation+1 || n.inc != inc || n.r != r || n.signer != signer || n.log != log || n.jw != journal || n.tr != transport || n.clock != clock || n.r.Vars().View.Sequence.Cmp(n.app.chain.head.Header.Number.AddUint64(1)) != 0 {
		t.Fatal("core did not restart against the imported head")
	}
	if len(s.viol) > 0 {
		t.Fatal(s.viol)
	}
}

func TestEngineRestartReplaysSameHeightWithExistingSigner(t *testing.T) {
	keys := testValidators(t, 4)
	cut := [][2]types.Address{}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			cut = append(cut, [2]types.Address{addrOf(keys[i]), addrOf(keys[j])})
		}
	}
	s, err := newSimulation(Scenario{Validators: keys, Partitions: []Partition{{From: 0, To: time.Minute, Cut: cut}}, Until: Stop{Duration: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	for _, n := range s.nodes {
		n.start()
		defer n.stop()
	}
	var n *node
	advanceEngineTest(t, s, 5*time.Second, func() bool {
		for _, candidate := range s.nodes {
			if _, ok := candidate.signer.LastHeight(); ok {
				n = candidate
				return true
			}
		}
		return false
	})
	before, signer, log, generation := n.r.Vars(), n.signer, n.log, n.r.EngineRun()
	n.requestEngineAction(ActionEngineStop)
	s.pumpAll()
	n.requestEngineAction(ActionEngineStart)
	s.pumpAll()
	after := n.r.Vars()
	replay := n.r.LastReplay()
	if !n.r.Running() || n.signer != signer || n.log != log || n.r.EngineRun() != generation+1 || !n.spec.ReplayWAL || !replay.Replayed || after.View.Sequence.Cmp(before.View.Sequence) != 0 || after.View.Round.Cmp(before.View.Round) != 0 || after.PreprepareSent.Cmp(before.PreprepareSent) != 0 || len(s.viol) > 0 {
		t.Fatal("same-height engine replay lost recorded state", replay, before, after, s.viol)
	}
}

func blockedEngineCommit(t *testing.T) (*node, *sealingBuilder, string) {
	t.Helper()
	_, n, b, id := sealingAssembly(t)
	t.Cleanup(n.crash)
	block := b.jobs[id].block
	if err := b.seals.Begin(taskqueue.SealRequest{ID: id, Hash: [32]byte(codec.BlockHash(block.Header))}); err != nil {
		t.Fatal(err)
	}
	b.sealEffects(b.seals.Acquire(id))
	b.commit(block, func(err error) {
		if err != nil {
			t.Error(err)
		}
	})
	n.r.Submit(block)
	for i := 0; !b.seals.CommitBlocked() && i < 100; i++ {
		if !n.r.Pump() {
			break
		}
	}
	if !b.seals.CommitBlocked() {
		t.Fatal("real runner did not reach blocked manual finalization")
	}
	if err := n.r.Stop(); !errors.Is(err, runner.ErrFinalizePending) {
		t.Fatal("fixture did not retain a real pending runner commit", err)
	}
	return n, b, id
}

func TestEngineControlWaitsForManualCommitHandoff(t *testing.T) {
	n, b, id := blockedEngineCommit(t)
	generation, inc, r := n.r.EngineRun(), n.inc, n.r
	n.requestEngineAction(ActionEngineStop)
	n.requestEngineAction(ActionEngineStart)
	if n.pumpEngineActions() || !n.r.Running() || n.r.EngineRun() != generation || len(n.engineActions) != 2 || b.closing || !n.alive {
		t.Fatal("engine control overtook blocked finalization")
	}
	b.sealEffects(b.seals.ChooseCommit(id))
	b.sealEffects(b.seals.AcceptCommit())
	if !n.pumpEngineActions() || !n.r.Running() || n.r.EngineRun() != generation+1 || n.inc != inc || n.r != r || len(n.engineActions) != 0 || b.closing || len(n.s.viol) > 0 {
		t.Fatal("ordered engine control did not resume after handoff", n.s.viol)
	}
}

func TestFullNodeStopFencesEngineControlsWhileCommitBlocked(t *testing.T) {
	n, b, _ := blockedEngineCommit(t)
	n.requestEngineAction(ActionEngineStop)
	n.requestEngineAction(ActionEngineStart)
	generation := n.r.EngineRun()
	n.stop()
	n.requestEngineAction(ActionEngineStart)
	n.requestEngineAction(ActionEngineStop)
	if len(n.engineActions) != 0 || !n.down || !b.stopRequested || !b.seals.CommitBlocked() || !n.r.Running() || n.r.EngineRun() != generation || n.pumpEngineActions() {
		t.Fatal("engine controls crossed an in-progress full node stop")
	}
}

func TestScheduledEngineActionsKeepOneNodeWriter(t *testing.T) {
	keys := testValidators(t, 4)
	target := addrOf(keys[3])
	result, err := Run(context.Background(), Scenario{Validators: keys, Until: Stop{Height: 10, Duration: 30 * time.Second}, Schedule: []NodeEvent{
		{Node: target, At: 2 * time.Second, Action: ActionEngineStop},
		{Node: target, At: 5 * time.Second, Action: ActionEngineStart},
	}}, Output{})
	if err != nil || len(result.Violations) > 0 {
		t.Fatal(err, result.Violations)
	}
	starts, pauses, resumes, writers := 0, 0, 0, 0
	for _, raw := range result.Events {
		found := false
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var row struct {
				Node string     `json:"node"`
				Kind event.Kind `json:"kind"`
				Mono int64      `json:"t_mono_ns"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if row.Node != hexAddr(target) {
				continue
			}
			found = true
			if row.Kind == event.NodeStart {
				starts++
			}
			if row.Kind == event.EngineStop && row.Mono == int64(2*time.Second) {
				pauses++
			}
			if row.Kind == event.EngineStart && row.Mono == int64(5*time.Second) {
				resumes++
			}
		}
		if found {
			writers++
		}
	}
	if starts != 1 || pauses != 1 || resumes != 1 || writers != 1 {
		t.Fatal("engine actions fabricated a node incarnation", starts, pauses, resumes, writers)
	}
}

func TestFullNodeRestartDiscardsPendingEngineControls(t *testing.T) {
	s, err := newSimulation(Scenario{Validators: testValidators(t, 1), Until: Stop{Duration: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	n := s.nodes[0]
	n.start()
	defer n.stop()
	r, inc := n.r, n.inc
	n.requestEngineAction(ActionEngineStop)
	n.requestEngineAction(ActionEngineStart)
	n.stop()
	n.start()
	s.pumpAll()
	if !n.alive || n.down || !n.r.Running() || n.r == r || n.inc != inc+1 || len(n.engineActions) != 0 || n.r.EngineRun() != 1 || len(s.viol) != 0 {
		t.Fatal("previous incarnation's engine control survived node restart", s.viol)
	}
}
