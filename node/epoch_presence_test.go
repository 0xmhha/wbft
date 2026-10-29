package node

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// An observer reads fresh unsigned metadata; no malformed block is imported.
func TestEpochPresenceReachesNodeHeaderVerifier(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			raw, g := testGenesis(t, testKey(0))
			a := newTestApp(raw, g)
			cfg, err := types.ParseChainConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			if enabled {
				names = []string{"check_epoch_info_presence"}
			}
			clock := futureHeaderClock{Clock: runner.SystemClock(), at: time.Unix(int64(g.Header.Time)+1000, 0)}
			n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a, fs: fsys.NewMem(), clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			a.cons = n.Consensus()
			if err = n.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer stop(t, n)
			if n.view.env("").CheckEpochInfoPresence != enabled || n.coreImprovements.Has(consensus.CheckEpochInfoPresence) != enabled {
				t.Fatal("selected verifier did not use frozen node policy")
			}
			reported := false
			for _, option := range n.improvements() {
				if option.Name == "check_epoch_info_presence" {
					if option.Source != "node" {
						t.Fatal("wrong option source")
					}
					reported = true
				}
			}
			if reported != enabled {
				t.Fatal("effective declaration differs from selection")
			}
			h := &types.Header{Number: types.HeightFromUint64(1), ParentHash: codec.BlockHash(g.Header), Coinbase: cfg.Init.Validators[0], Difficulty: big.NewInt(1), Time: g.Header.Time + cfg.ConfigAt(types.HeightFromUint64(1)).BlockPeriodSeconds}
			if err = codec.SetExtra(h, &types.WBFTExtra{GasTip: big.NewInt(0), EpochInfo: &types.EpochInfo{}}); err != nil {
				t.Fatal(err)
			}
			err = n.Consensus().VerifyHeader(context.Background(), h, app.VerifyOptions{CheckSeals: false})
			if enabled && !errors.Is(err, epoch.ErrEpochInfoIsNotNil) || !enabled && !errors.Is(err, header.ErrInvalidRandaoReveal) {
				t.Fatal("node unsigned metadata ordering", enabled, err)
			}
		})
	}
	selected, ok := consensus.ParseImprovement("check_epoch_info_presence")
	if !ok || selected != consensus.CheckEpochInfoPresence || !consensus.KnownImprovements().Has(selected) || consensus.RestartSafety.Has(selected) {
		t.Fatal("selection registry or defaults changed")
	}
}
