package runner

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type historicalChain struct {
	*fakeChain
	past        *validator.Set
	unavailable bool
}

func (c *historicalChain) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	h := c.Head()
	if n.Cmp(h.Number) == 0 && parent == h.ParentHash {
		if c.unavailable {
			return nil, errors.New("normal historical lookup unavailable")
		}
		return c.past, nil
	}
	if n.Cmp(h.Number.AddUint64(1)) == 0 && parent == codec.BlockHash(h) {
		return c.vs, nil
	}
	return nil, errors.New("lookup outside adopted header context")
}

func TestBindPriorHeadRunnerCloseOpenPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, unavailable := range []bool{false, true} {
			for _, deferred := range []bool{false, true} {
				t.Run(fmt.Sprintf("enabled%t/unavailable%t/deferred%t", enabled, unavailable, deferred), func(t *testing.T) {
					k := newKeys(t, 4)
					head := block(t, 10, 1, k.addrs[0], types.Hash{9})
					var ps, cs []types.SealEntry
					for _, i := range []int{0, 1, 2} {
						ps = append(ps, types.SealEntry{Sealer: uint32(i), Seal: k.bls[i].Sign(codec.SealData(head.Header, 0, types.PrepareSeal)).Bytes()})
						cs = append(cs, types.SealEntry{Sealer: uint32(i), Seal: k.bls[i].Sign(codec.SealData(head.Header, 0, types.CommitSeal)).Bytes()})
					}
					sealed, err := header.CommitHeader(head, types.Round{}, ps, cs)
					if err != nil {
						t.Fatal(err)
					}
					clock := &manualClock{}
					chain := &historicalChain{fakeChain: &fakeChain{head: sealed.Header, vs: nextHeightSet(t, k, []int{1, 2, 3}), clock: clock, future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}, past: k.vs, unavailable: unavailable}
					policy := uint64(0)
					opt := consensus.Options{Config: types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)}
					if enabled {
						opt.Improvements = opt.Improvements.With(consensus.BindPriorHead)
					}
					cfg := Config{Core: opt, ReplayWAL: true, Manual: true}
					if deferred {
						cfg.NextHeight = &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}
					}
					fs := fsys.NewMem()
					var first *consensus.Snapshot
					for startup := 0; startup < 2; startup++ {
						log, _, err := wal.Open(fs, "/wal", wal.Options{SegmentBytes: 4096, KeepHeights: 2})
						if err != nil {
							t.Fatal(err)
						}
						r, err := New(cfg, Deps{Chain: chain, App: &fakeApp{}, Clock: clock, WAL: log, Rand: func(int) int { return 0 }})
						if err != nil {
							_ = log.Close()
							t.Fatal(err)
						}
						t.Cleanup(func() {
							_ = r.Close()
							_ = log.Close()
						})
						if err = r.Start(context.Background(), types.HeightFromUint64(11)); err != nil {
							_ = r.Close()
							_ = log.Close()
							t.Fatal(err)
						}
						if startup == 0 {
							if enabled && !unavailable {
								p := k.vote(t, 0, codec.CodePrepare, view(10, 0), sealed)
								r.Receiver().Offer(transport.Inbound{Peer: k.addrs[0], Code: uint64(codec.CodePrepare), Payload: p})
								deadline := time.Now().Add(5 * time.Second)
								for len(r.Snapshot().ExtraPrepare) == 0 && time.Now().Before(deadline) {
									r.Pump()
									time.Sleep(time.Millisecond)
								}
								if len(r.Snapshot().ExtraPrepare) != 1 {
									t.Fatal("normal historical vote did not arrive")
								}
							}
							r.Submit(block(t, 11, 1, k.addrs[1], codec.BlockHash(sealed.Header)))
							r.Pump()
							first = r.Snapshot()
						} else {
							got := r.Snapshot()
							if !r.LastReplay().Replayed || got.View.Cmp(first.View) != 0 || got.Validators.Len() != first.Validators.Len() || len(got.ExtraPrepare) != len(first.ExtraPrepare) {
								t.Fatal("normal WAL recovery changed state", r.LastReplay())
							}
						}
						snap := r.Snapshot()
						if enabled {
							if snap.PriorSource == nil || snap.PriorSource.ValidateHead(sealed.Header) != nil || snap.Validators.Len() != 3 || snap.PriorValidators == nil {
								t.Fatal("prior source missing after start/recovery")
							}
							if unavailable && snap.PriorSource.Validators != nil || !unavailable && snap.PriorValidators.Len() != 4 {
								t.Fatal("unavailable or historical set was substituted")
							}
						} else if snap.PriorSource != nil {
							t.Fatal("default source behavior changed")
						}
						if err = r.Close(); err != nil {
							t.Fatal(err)
						}
						if err = log.Close(); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}
