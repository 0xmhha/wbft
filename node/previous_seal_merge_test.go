// SPDX-FileCopyrightText: 2026 The wbft authors
// SPDX-License-Identifier: LGPL-3.0-or-later

package node

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// The application constructs ordinary empty blocks through the actual node
// service. Each lifetime stops normally; no packet or transaction is injected.
func TestNodeVerifiedPreviousSealsNormalRestart(t *testing.T) {
	for _, item := range []struct {
		name          string
		verify, prior bool
	}{
		{name: "off"},
		{name: "verify", verify: true},
		{name: "prior", prior: true},
		{name: "both", verify: true, prior: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			key := testKey(0)
			raw, genesis := testGenesis(t, key)
			parsed, err := types.ParseChainConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			a, mem := newTestApp(raw, genesis), fsys.NewMem()
			var previous uint64
			for lifetime := range 2 {
				// Reconstruct the caller's selection on every ordinary restart.
				var names []string
				if item.prior {
					names = append(names, "bind_prior_head")
				}
				if item.verify {
					names = append(names, "verify_merged_prev_seals")
				}
				events := &syncBuffer{}
				n, err := New(Config{DataDir: "/data", TakeoverGuard: true, Improvements: names}, Deps{App: a, Authority: a, fs: mem, key: key, Events: events})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { stop(t, n) })
				for i := range names {
					names[i] = "keep_stopped_peers"
				}
				if n.coreImprovements.Has(consensus.VerifyMergedPrevSeals) != item.verify || n.coreImprovements.Has(consensus.BindPriorHead) != item.prior {
					t.Fatal("caller changed the frozen node selection")
				}
				a.cons = n.Consensus()
				if err := n.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				target := uint64(3)
				if lifetime > 0 {
					target = previous + 2
				}
				a.waitHead(t, target, 20*time.Second)
				if err := n.Stop(); err != nil {
					t.Fatal(err)
				}
				previous = a.Head().Number.RefLow64() //wbft:low64 HH-60
				found := false
				for _, option := range (backend{n}).NodeInfo().Improvements {
					if option.Name == "verify_merged_prev_seals" && option.Source == "node" {
						found = true
					}
				}
				if found != item.verify {
					t.Fatal("nodeInfo lost the frozen verification selection")
				}
				starts := 0
				for _, line := range strings.Split(events.String(), "\n") {
					if line == "" {
						continue
					}
					var record struct {
						Kind         string `json:"kind"`
						Improvements []struct {
							Name   string `json:"name"`
							Source string `json:"source"`
						} `json:"improvements"`
					}
					if err := json.Unmarshal([]byte(line), &record); err != nil {
						t.Fatal(err)
					}
					if record.Kind != "NODE_START" {
						continue
					}
					starts++
					selected := false
					for _, option := range record.Improvements {
						if option.Name == "verify_merged_prev_seals" && option.Source == "node" {
							selected = true
						}
					}
					if selected != item.verify {
						t.Fatal("NODE_START lost the selected local behavior")
					}
				}
				if starts != 1 {
					t.Fatal("ordinary node lifetime declaration missing", starts)
				}
				for number := uint64(2); number <= previous; number++ {
					h := a.HeaderByNumber(number)
					parent := a.Header(h.ParentHash, number-1)
					x, err := codec.DecodeConsensusExtra(h)
					if err != nil {
						t.Fatal(err)
					}
					px, err := codec.DecodeConsensusExtra(parent)
					if err != nil || x.PrevRound != px.Round {
						t.Fatal("actual proposal lost its parent round", err)
					}
					set, err := validator.ValidatorsAt(a, parsed, parent.Number, parent.ParentHash, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := header.VerifyAggregatedSeal(set, parent, x.PrevRound, x.PrevPreparedSeal, types.PrepareSeal); err != nil {
						t.Fatal("actual proposal's previous prepared seal does not verify", err)
					}
					if err := header.VerifyAggregatedSeal(set, parent, x.PrevRound, x.PrevCommittedSeal, types.CommitSeal); err != nil {
						t.Fatal("actual proposal's previous committed seal does not verify", err)
					}
				}
				if state, err := mem.ReadFile("/data/privval/state"); err != nil || len(state) == 0 {
					t.Fatal("normal stored signing state missing", err)
				}
				if records, _, err := wal.ReadAll(mem, "/data/wal"); err != nil || len(records) == 0 {
					t.Fatal("normal consensus WAL missing", err)
				}
				t.Logf("normal_previous_seal_node verify=%t prior=%t lifetime=%d height=%d actual_service=true previous_seals_verified=true new_transactions=0", item.verify, item.prior, lifetime, previous)
			}
			records, err := journal.ReadAll(mem, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			segments := 0
			for _, record := range records {
				if segment, ok := record.Body.(*journal.SegmentRec); ok {
					segments++
					selected := consensus.ImprovementSet(segment.Core.Improvements)
					if selected.Has(consensus.VerifyMergedPrevSeals) != item.verify || selected.Has(consensus.BindPriorHead) != item.prior {
						t.Fatal("original journal declaration lost the selected behavior")
					}
				}
			}
			if segments < 2 {
				t.Fatal("stored lifetime declarations missing", segments)
			}
			reader, err := journal.OpenReader(mem, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			steps, starts := 0, 0
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: appBlocks{a}}, func(s stepdriver.StepResult) error {
				steps++
				if s.Step == 1 {
					starts++
				}
				if !s.Match {
					return fmt.Errorf("core step mismatch in run %d step %d", s.EngineRun, s.Step)
				}
				return nil
			})
			if err != nil || steps < 10 || starts != 2 {
				t.Fatal("normal stored core-step replay mismatch", err, steps, starts)
			}
			t.Logf("normal_previous_seal_core_steps=%d starts=%d header_construction_reexecuted=false physical_reconstruction=false", steps, starts)
		})
	}
}
