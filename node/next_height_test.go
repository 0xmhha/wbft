package node

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type nextHeightBuildGate struct {
	*testApp
	ready <-chan struct{}
}

type nextHeightReaderOnly struct{ stepdriver.JournalReader }

func (a *nextHeightBuildGate) ReadyToBuild(req app.BuildRequest) {
	go func() {
		select {
		case <-a.ready:
			a.testApp.ReadyToBuild(req)
		case <-req.Done:
		}
	}()
}

func TestNextHeightNodeProfileAndReplay(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			key := testKey(0)
			cj, g := testGenesis(t, key)
			a := newTestApp(cj, g)
			ready := make(chan struct{})
			var once sync.Once
			resume := func() { once.Do(func() { close(ready) }) }
			t.Cleanup(resume)
			fs := fsys.NewMem()
			cfg := Config{DataDir: "/data"}
			want := journal.DeferredOptions{Profile: journal.DeferredInputProfile, Entries: 12, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}
			if enabled {
				cfg.NextHeight = &runner.NextHeightLimits{Entries: want.Entries, Bytes: want.Bytes, PerPeer: want.PerPeer, PerSource: want.PerSource}
			}
			n, err := New(cfg, Deps{App: &nextHeightBuildGate{testApp: a, ready: ready}, Authority: a, fs: fs, key: key})
			if err != nil {
				t.Fatal(err)
			}
			if enabled {
				cfg.NextHeight.Bytes = 1
			} // Caller storage is no longer owned by the node.
			a.cons = n.Consensus()
			if err := n.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stop(t, n) })
			if enabled {
				k, err := ecdsa.PrivateKeyFromBytes(key)
				if err != nil {
					t.Fatal(err)
				}
				m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(2), Round: types.RoundFromUint64(1)}}
				p, err := codec.SigningPayload(m, false, nil)
				if err != nil {
					t.Fatal(err)
				}
				m.Signature, err = ecdsa.SignData(p, k)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := codec.EncodeMessage(m)
				if err != nil {
					t.Fatal(err)
				}
				peer, mono := ecdsa.Address(k), n.clock.Mono()
				n.journal.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: peer, Event: "attached"}})
				n.journal.Put(journal.Record{Body: &journal.MsgRec{Capture: 17, Dir: journal.In, PeerIdx: 2, Code: uint64(m.Code), Payload: raw, Mono: mono, Offer: transport.OfferQueued}})
				if !n.r.Receiver().Offer(transport.Inbound{Capture: 17, Peer: peer, Code: uint64(m.Code), Payload: raw, RecvMono: mono}) {
					t.Fatal("normal next-height message refused")
				}
			}
			resume()
			a.waitHead(t, 2, 20*time.Second)
			stop(t, n)
			records, err := journal.ReadAll(fs, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			segments := 0
			for _, rec := range records {
				if seg, ok := rec.Body.(*journal.SegmentRec); ok {
					segments++
					if enabled && !reflect.DeepEqual(seg.Core.NextHeight, &want) || !enabled && seg.Core.NextHeight != nil {
						t.Fatalf("wrong recorded profile: %+v", seg.Core.NextHeight)
					}
				}
			}
			r, err := journal.OpenReader(fs, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			steps, deferred := 0, 0
			var states []string
			err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: appBlocks{a}, WithVars: true}, func(s stepdriver.StepResult) error {
				steps++
				states = append(states, s.OutDigest.Hex()+stepdriver.VarsJSON(s.Vars))
				if !s.Match {
					return fmt.Errorf("step %d differs", s.Step)
				}
				if s.DeferredOrigin != nil {
					deferred++
					if s.DeferredOrigin.Status != "verified" || s.DeferredOrigin.Origin.Capture != 17 {
						return fmt.Errorf("source unavailable: %+v", s.DeferredOrigin)
					}
				}
				return nil
			})
			if err != nil || segments == 0 || steps == 0 {
				t.Fatalf("journal replay: segments=%d steps=%d err=%v", segments, steps, err)
			}
			if enabled && deferred != 1 || !enabled && deferred != 0 {
				t.Fatalf("deferred release count: %d", deferred)
			}
			r, err = journal.OpenReader(fs, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			var noObserver []string
			err = stepdriver.RunTrace(nextHeightReaderOnly{r}, stepdriver.TraceOptions{Blocks: appBlocks{a}, WithVars: true}, func(s stepdriver.StepResult) error {
				if !s.Match {
					return fmt.Errorf("no-observer step %d differs", s.Step)
				}
				noObserver = append(noObserver, s.OutDigest.Hex()+stepdriver.VarsJSON(s.Vars))
				if s.DeferredOrigin != nil && (s.DeferredOrigin.Status != "unavailable" || s.DeferredOrigin.Reason != "capture_resolver_unavailable") {
					return fmt.Errorf("physical source was fabricated: %+v", s.DeferredOrigin)
				}
				return nil
			})
			if err != nil || !reflect.DeepEqual(states, noObserver) {
				t.Fatalf("functional replay depends on capture observer: %v", err)
			}
		})
	}
}
