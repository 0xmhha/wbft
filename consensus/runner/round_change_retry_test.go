package runner

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
)

type normalRetrySignerCalls struct{ calls []journal.SignerCallRec }

func (o *normalRetrySignerCalls) ObserveSignerCall(s journal.SignerCallRec) {
	o.calls = append(o.calls, s)
}

// The normal manual clock fires real scheduler callbacks; FileSigner and WAL
// run normally. The transport is a queue fixture, not a physical write proof.
func TestNormalRoundChangeRetryRunnerPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 3)
			n.noJournal = true // The new journal declaration is a separate integration.
			calls := &normalRetrySignerCalls{}
			n.signerCalls = calls
			if enabled {
				n.opts.RoundChangeRetry = &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
			}
			n.boot()
			t.Cleanup(func() { _ = n.r.Close(); _ = n.log.Close() })
			// Reach a normally timed round whose round reservation is long
			// enough to observe the retry cap without changing timer inputs.
			for round := uint64(1); round <= 6; round++ {
				arm := n.r.timers.live[consensus.RoundTimer].arm
				n.advance(arm.Duration)
				if n.r.Vars().View.Cmp(view(10, round)) != 0 {
					t.Fatal("ordinary round expiry did not advance", round, n.r.Vars())
				}
			}
			first := bytes.Clone(n.net.own(codec.CodeRoundChange)[len(n.net.own(codec.CodeRoundChange))-1])
			beforeSends, beforeCalls := len(n.net.own(codec.CodeRoundChange)), len(calls.calls)
			for i, next := range []time.Duration{4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second} {
				entry := n.r.timers.live[consensus.RetryTimer]
				wantDelay := 2 * time.Second
				if enabled && i > 0 {
					wantDelay = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}[i]
				}
				if entry == nil || entry.arm.Duration != wantDelay {
					t.Fatal("actual scheduled retry delay", i, entry)
				}
				n.advance(wantDelay)
				if enabled {
					if n.r.timers.live[consensus.RetryTimer].arm.Duration != next || len(n.net.own(codec.CodeRoundChange)) != beforeSends+i+1 {
						t.Fatal("retry did not reach the ordinary transport queue", i)
					}
				} else if len(n.net.own(codec.CodeRoundChange)) != beforeSends {
					t.Fatal("disabled recent-cache suppression changed")
				}
				last := calls.calls[len(calls.calls)-1]
				if len(calls.calls) != beforeCalls+i+1 || last.Reused != 1 || last.WALWritten != 1 || !bytes.Equal(last.Payload, first) || last.Result != "sent" {
					t.Fatal("actual persisted signer/WAL did not reuse identical bytes", i, last.Result)
				}
			}
			for _, wire := range n.net.own(codec.CodeRoundChange)[beforeSends:] {
				if !bytes.Equal(wire, first) {
					t.Fatal("same-view signed bytes changed")
				}
			}
			if enabled {
				before := *n.r.Vars().RoundChangeRetry
				if err := n.r.Close(); err != nil {
					t.Fatal(err)
				}
				if err := n.log.Close(); err != nil {
					t.Fatal(err)
				}
				n.boot()
				after := n.r.Vars().RoundChangeRetry
				entry := n.r.timers.live[consensus.RetryTimer]
				if after == nil || after.Key != before.Key || after.Exponent != before.Exponent || after.View.Cmp(before.View) != 0 ||
					!n.r.LastReplay().Replayed || entry == nil || entry.from != n.clock.now || entry.arm.Duration != 8*time.Second {
					t.Fatal("normal close/open lost retry identity or fresh full interval", n.r.LastReplay(), after)
				}
			}
		})
	}
}
