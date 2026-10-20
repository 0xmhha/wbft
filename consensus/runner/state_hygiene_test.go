package runner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// Replay ordinary recorded inputs against their environment answers. No
// packet mutations, crashes or fault points are introduced by this control.
func assertStateHygieneJournal(t *testing.T, n *tnode) {
	t.Helper()
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	core := consensus.NewState(n.opts)
	env := &replayEnv{head: n.chain.head}
	steps := 0
	for _, record := range records {
		step, ok := record.Body.(*journal.StepRec)
		if !ok {
			continue
		}
		steps++
		input, err := inputlog.Decode(step.InputKind, step.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		env.answers, env.err = nil, nil
		for _, raw := range step.Env {
			answer, err := inputlog.DecodeEnv(raw)
			if err != nil {
				t.Fatal(err)
			}
			env.answers = append(env.answers, answer)
		}
		var out []consensus.Output
		if step.InputKind == inputlog.KindStart {
			out = core.Step(&startEnv{head: n.chain.head, vs: n.k.vs}, input)
		} else {
			out = core.Step(env, input)
		}
		digest, err := inputlog.OutDigest(out)
		if err != nil || digest != step.OutDigest || env.err != nil || len(env.answers) != 0 {
			t.Fatal("journal replay diverged", step.Step, err, env.err)
		}
	}
	if steps == 0 || !reflect.DeepEqual(core.Vars(), n.r.Vars()) {
		t.Fatal("normal journal final state differs")
	}
}

func TestBoundCertificateJournalAndNormalRestartPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "bound"}[enabled], func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			if enabled {
				n.opts.Improvements = n.opts.Improvements.With(consensus.BindPreparedCertificate)
			}
			n.boot()
			b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
			reachPrepared(t, n, b)
			n.advance(2 * time.Second)
			before := n.r.Vars()
			if before.LockedBlock == nil || len(before.Certificate) != 3 || before.View.Cmp(view(10, 1)) != 0 {
				t.Fatal("ordinary round lost prepared state", before)
			}
			assertStateHygieneJournal(t, n)
			// This replay control covers durable inputs. A legacy request that
			// produces no own signature does not itself force a WAL sync.
			if err := n.log.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
				t.Fatal(err)
			}
			n.r.Pump()
			info := n.r.LastReplay()
			after := n.r.Vars()
			if !info.Replayed || info.Stopped != "" || info.Records == 0 || !reflect.DeepEqual(before, after) || len(n.refused) != 0 {
				t.Fatal("normal WAL restart changed prepared state", info, before, after, n.refused)
			}
		})
	}
}

func TestDelayedRoundProposalJournalAndNormalRestartPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "resume"}[enabled], func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			if enabled {
				n.opts.Improvements = n.opts.Improvements.With(consensus.ResumeRoundProposals)
			}
			n.boot()
			n.advance(2 * time.Second)
			for _, i := range []int{0, 2} {
				n.deliver(i, codec.CodeRoundChange, k.sign(t, i, &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, nil))
			}
			if len(n.net.own(codec.CodePreprepare)) != 0 {
				t.Fatal("proposal sent before builder request")
			}
			b := block(t, 10, 1, k.addrs[1], codec.BlockHash(n.chain.head))
			n.r.Submit(b)
			n.r.Pump()
			want := 0
			if enabled {
				want = 1
			}
			if len(n.net.own(codec.CodePreprepare)) != want || len(n.refused) != 0 {
				t.Fatal("late builder behavior", n.refused)
			}
			assertStateHygieneJournal(t, n)
			before := n.r.Vars()
			// This replay control covers durable inputs. A legacy request that
			// produces no own signature does not itself force a WAL sync.
			if err := n.log.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
				t.Fatal(err)
			}
			n.r.Pump()
			if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" || !reflect.DeepEqual(before, n.r.Vars()) || len(n.refused) != 0 {
				t.Fatal("normal WAL restart changed delayed proposal state", info, n.refused)
			}
		})
	}
}
