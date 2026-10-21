package runner

import (
	"context"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestKeepStoppedPeersNormalPausePair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, syncing := range []bool{false, true} {
			for _, paused := range []bool{false, true} {
				t.Run(fmt.Sprintf("enabled_%t/syncing_%t/paused_%t", enabled, syncing, paused), func(t *testing.T) {
					k := newKeys(t, 4)
					n := newTNode(t, k, 1)
					if enabled {
						n.opts.Improvements = n.opts.Improvements.With(consensus.KeepStoppedPeers)
					}
					n.boot()
					t.Cleanup(func() { _ = n.r.Close() })
					n.r.d.Synchronising = func() bool { return syncing }
					a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
					payload := k.vote(t, 0, codec.CodePrepare, view(10, 0), a)
					verified, err := consensus.Recover(codec.CodePrepare, payload, nil)
					if err != nil || verified.Source != k.addrs[0] || verified.Msg.Digest != codec.BlockHash(a.Header) {
						t.Fatal("normal signed control did not verify", err)
					}
					if paused {
						if err := n.r.Stop(); err != nil {
							t.Fatal(err)
						}
					}
					if !n.r.Receiver().Offer(transportInbound(k, 0, codec.CodePrepare, payload, 0)) {
						t.Fatal("normal frame was rejected by queue admission")
					}
					wantDisconnect := paused && !syncing && !enabled
					if (len(n.net.discon) == 1) != wantDisconnect || len(n.net.discon) > 1 {
						t.Fatal("normal engine state changed the wrong connection policy", n.net.discon)
					}
					if !paused {
						n.r.Pump()
						if !n.r.d.Transport.Known(payload) {
							t.Fatal("running engine lost the normal receive path")
						}
						return
					}
					n.r.inbox.mu.Lock()
					queued, slots := n.r.inbox.queuedLocked(), len(n.r.inbox.slots)
					n.r.inbox.mu.Unlock()
					if n.r.d.Transport.Known(payload) || queued || slots != 0 {
						t.Fatal("paused frame entered a cache or receive queue")
					}
					if n.r.Vars() != nil || n.r.Running() {
						t.Fatal("paused receive recreated a running consensus state")
					}
					want := "DROP_SILENT"
					if wantDisconnect {
						want = "DISCONNECT"
					}
					var outcomes []string
					for _, e := range n.events.kinds(event.MsgOutcome) {
						if e.Fields["reason"] == "engine_stopped" {
							outcomes = append(outcomes, fmt.Sprint(e.Fields["outcome"]))
						}
					}
					if len(outcomes) != 1 || outcomes[0] != want {
						t.Fatal("paused outcome does not describe the selected behavior", outcomes)
					}
					if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
						t.Fatal(err)
					}
					if !n.r.Running() || n.r.EngineRun() != 2 {
						t.Fatal("normal engine restart failed")
					}
					n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), a))
					n.deliver(0, codec.CodePrepare, payload)
					n.deliver(2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), a))
					if n.r.Vars().State != consensus.Prepared || !n.r.d.Transport.Known(payload) {
						t.Fatal("normal proposal and prepare quorum did not resume after pause", n.r.Vars())
					}
				})
			}
		}
	}
}
