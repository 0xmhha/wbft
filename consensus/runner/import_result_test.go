package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestImportResultBindingJournalAndWALReplay(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "watchdog"}[watch], func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			if watch {
				n.opts.Improvements = n.opts.Improvements.With(consensus.WatchCommittedImport)
			}
			n.boot()
			a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
			reachPrepared(t, n, a)
			n.deliver(0, codec.CodeCommit, k.vote(t, 0, codec.CodeCommit, view(10, 0), a))
			n.deliver(2, codec.CodeCommit, k.vote(t, 2, codec.CodeCommit, view(10, 0), a))
			if n.r.Vars().State != consensus.Committed {
				t.Fatal("not decided")
			}
			if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
				t.Fatal(err)
			}
			recs, err := journal.ReadAll(n.jfs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			core := consensus.NewState(n.opts)
			env := &replayEnv{head: n.chain.head}
			for _, rec := range recs {
				step, ok := rec.Body.(*journal.StepRec)
				if !ok {
					continue
				}
				in, err := inputlog.Decode(step.InputKind, step.Input, nil)
				if err != nil {
					t.Fatal(err)
				}
				if result, ok := in.(consensus.CommitResult); ok {
					seen++
					if (result.View != nil) != watch || result.Hash != codec.BlockHash(a.Header) {
						t.Fatal("import result binding changed", result)
					}
					if watch && result.View.Cmp(view(10, 0)) != 0 {
						t.Fatal("result belongs to another view")
					}
				}
				env.answers, env.err = nil, nil
				for _, raw := range step.Env {
					answer, err := inputlog.DecodeEnv(raw)
					if err != nil {
						t.Fatal(err)
					}
					env.answers = append(env.answers, answer)
				}
				var outs []consensus.Output
				if step.InputKind == inputlog.KindStart {
					outs = core.Step(&startEnv{head: n.chain.head, vs: k.vs}, in)
				} else {
					outs = core.Step(env, in)
				}
				digest, err := inputlog.OutDigest(outs)
				if err != nil || digest != step.OutDigest || env.err != nil || len(env.answers) != 0 {
					t.Fatal("journal replay mismatch", step.Step, err, env.err)
				}
			}
			if seen != 1 {
				t.Fatal("missing or repeated actual application result", seen)
			}
			n.crash()
			n.net.sent = nil
			n.boot()
			if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" {
				t.Fatal("WAL replay stopped", info)
			}
			n.advance(3 * time.Second)
			if watch {
				if !n.r.Vars().View.Round.IsZero() || len(n.net.own(codec.CodeRoundChange)) != 0 {
					t.Fatal("success lost during replay")
				}
			} else if len(n.net.own(codec.CodeRoundChange)) != 1 {
				t.Fatal("legacy timer no longer runs")
			}
		})
	}
}
