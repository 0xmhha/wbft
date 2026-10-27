package runner

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestNormalRetryQueuedBeforeProposalHasNoCurrentException(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprint(cancel), func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 2)
			raw := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
			config, err := types.ParseChainConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			n.opts.Config, n.opts.RoundChangeRetry = config, &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
			if cancel {
				n.opts.Improvements = n.opts.Improvements.With(consensus.CancelStaleRetries)
			}
			n.noJournal = true
			w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/phase-source", Synchronous: true}, journal.Identity{Self: k.addrs[2], Run: "normal-proposal-phase", Core: journal.CoreOptions{Self: k.addrs[2], ChainConfig: raw, Improvements: uint64(n.opts.Improvements), TimerTrace: journal.TimerTraceVersion, CacheTrace: journal.CacheTraceVersion,
				RoundChangeRetry: &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 8000}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = w.Close() })
			o := &normalRetrySources{writer: w, clock: n.clock, run: "normal-proposal-phase"}
			n.coreSteps, n.timerSources = o, o
			n.dedupTransport = normalRetryCacheTransport{fakeNet: n.net, source: o}
			n.boot()
			t.Cleanup(func() { _ = n.r.Close(); _ = n.log.Close() })
			n.advance(2 * time.Second)
			// One real existing callback queues before an ordinary proposal.
			// The scheduler's normal peer-first choice processes the proposal
			// before that callback; neither input nor queue contents are edited.
			n.clock.advance(n.clock.now + 2*time.Second)
			if !n.r.timers.pending() {
				t.Fatal("ordinary callback was not queued")
			}
			n.r.d.Rand = func(n int) int { return n - 1 }
			b := block(t, 10, 1, k.addrs[1], codec.BlockHash(n.chain.head))
			var certificate []*codec.Message
			for _, index := range []int{0, 1, 3} {
				message, err := codec.DecodeMessage(codec.CodeRoundChange, k.sign(t, index, &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, nil))
				if err != nil {
					t.Fatal(err)
				}
				certificate = append(certificate, message)
			}
			proposal := k.sign(t, 1, &codec.Message{Code: codec.CodePreprepare, View: view(10, 1), Proposal: b, RoundChanges: certificate}, nil)
			if !n.r.Receiver().Offer(transportInbound(k, 1, codec.CodePreprepare, proposal, n.clock.now)) {
				t.Fatal("normal proposal not admitted")
			}
			n.r.Pump()
			if n.r.Vars().State != consensus.Preprepared || len(n.refused) != 0 || len(n.net.own(codec.CodeRoundChange)) != 1 {
				t.Fatal("phase or original recent suppression changed", n.r.Vars(), n.refused)
			}
			if err := n.r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := n.log.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(n.jfs, "/phase-source")
			if err != nil {
				t.Fatal(err)
			}
			checked, err := journal.CheckCoreStepSources(records, journal.CoreSourceLimits{Records: 10000, Runs: 8, Steps: 1000, Environments: 10000, Outputs: 10000, Bytes: 16 << 20})
			if err != nil || checked.Status != "consistent" {
				t.Fatal("independent phase transcript differs", checked, err)
			}
			expiries := 0
			for _, record := range records {
				if op, ok := record.Body.(*journal.CacheRec); ok && op.Retry.Version != 0 {
					t.Fatal("post-proposal callback obtained a current retry exception")
				}
				if step, ok := record.Body.(*journal.CoreStepRec); ok && step.InputKind == inputlog.KindTimeout {
					input, err := inputlog.Decode(step.InputKind, step.Input, nil)
					if err != nil {
						t.Fatal(err)
					}
					if input.(consensus.Timeout).Kind == consensus.RetryTimer {
						expiries++
						if step.After.State != consensus.Preprepared.String() {
							t.Fatal("callback lost proposal phase")
						}
					}
				}
			}
			if expiries != 1 {
				t.Fatal("original callback was not consumed exactly once", expiries)
			}
		})
	}
}
