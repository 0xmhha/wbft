package kvstore

import (
	"fmt"
	"github.com/0xmhha/wbft/codec/rlp"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/node"
	checkpointstore "github.com/0xmhha/wbft/observe/window"
	"github.com/0xmhha/wbft/types"
)

func normalObservationPolicy(t *testing.T, g *Genesis) *node.ObservationConfig {
	t.Helper()
	genesis, err := g.block()
	if err != nil {
		t.Fatal(err)
	}
	return &node.ObservationConfig{Policy: state.Config{ChainID: big.NewInt(7), GenesisHash: codec.BlockHash(genesis.Header), Activation: types.HeightFromUint64(3), Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 32, SettlementRows: 64, Validators: 64}, StateBytes: 1 << 20, CheckpointBytes: 2 << 20, AddressRows: 64}, Retention: types.HeightFromUint64(3), HistoryWalk: 128, ReplayHeaders: 128, WitnessItems: 128, WitnessBytes: 1 << 20, WitnessChecksPerStep: 32}
}

// Both modes use ordinary own-node signatures, network delivery, transactions
// and normal shutdown/reopen. No timer or network fault is introduced.
func TestNormalObservationNodeOffOnAndRestart(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			configure := func(g *Genesis) *node.ObservationConfig {
				if !enabled {
					return nil
				}
				return normalObservationPolicy(t, g)
			}
			network := newTestNetWithObservation(t, 4, configure)
			bob := types.Address{0xb0}
			submit(t, network.nodes[0], Tx{From: bob, Nonce: 0, Key: "observation", Value: "normal"})
			waitFor(t, "normal carriers", 60*time.Second, func() bool {
				for _, nd := range network.nodes {
					if nd.App.Head().Number.CmpUint64(12) < 0 || nd.App.Nonce(bob) != 1 {
						return false
					}
				}
				return true
			})
			for i, nd := range network.nodes {
				if err := nd.Stop(); err != nil {
					t.Fatal(err)
				}
				network.nodes[i] = nil
			}
			for i := range network.nodes {
				network.open(i)
			}
			for i := range network.nodes {
				network.start(i)
			}
			waitFor(t, "normal resumed carriers", 60*time.Second, func() bool {
				for _, nd := range network.nodes {
					if nd.App.Head().Number.CmpUint64(18) < 0 {
						return false
					}
				}
				return true
			})
			// Close before independently reading checkpoints, so the trusted app head
			// and checkpoint cannot advance between reads.
			closedNodes := append([]*Node(nil), network.nodes...)
			for i, nd := range closedNodes {
				network.nodes[i] = nil
				if err := nd.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			for i, nd := range closedNodes {
				h := nd.App.BlockByNumber(18).Header
				if !enabled {
					if _, err := codec.DecodeExtra(h); err != nil {
						t.Fatal(err)
					}
				} else {
					policy := network.observation
					x, err := wire.Decode(h.Extra, policy.Policy.Codec)
					if err != nil || x.Observation.Version != 2 {
						t.Fatalf("carrier: %v", err)
					}
					hash, err := wire.BlockHash(h, policy.Policy.Codec)
					if err != nil || hash != codec.BlockHash(h) {
						t.Fatalf("identity: %v", err)
					}
					engine, err := state.NewRecent(policy.Policy, policy.Retention)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(network.homes[i], "consensus", "observation", "state.rlp")
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var hint struct {
						Version uint64
						Height  *big.Int
						Hash    types.Hash
						State   rlp.RawValue
					}
					if err := rlp.DecodeStrict(raw, &hint); err != nil {
						t.Fatal(err)
					}
					trusted := nd.App.Head()
					var suffix []*types.Header
					for codec.BlockHash(trusted) != hint.Hash {
						if len(suffix) >= 128 {
							t.Fatal("checkpoint not in trusted ancestry")
						}
						suffix = append(suffix, trusted)
						trusted = nd.App.HeaderByHash(trusted.ParentHash)
						if trusted == nil {
							t.Fatal("checkpoint ancestor missing")
						}
					}
					recovered, err := checkpointstore.Load(path, engine, trusted)
					if err != nil {
						t.Fatal(err)
					}
					chainConfig, err := types.ParseChainConfig(network.g.Config)
					if err != nil {
						t.Fatal(err)
					}
					history, err := state.NewBranchHistory(engine, nd.App, chainConfig, 128)
					if err != nil {
						t.Fatal(err)
					}
					for j := len(suffix) - 1; j >= 0; j-- {
						recovered, err = engine.VerifyAndApply(recovered, suffix[j], history)
						if err != nil {
							t.Fatal(err)
						}
					}
					from, through, ok := recovered.RecentWindow()
					if !ok || through.Big().Sub(through.Big(), from.Big()).Cmp(big.NewInt(2)) != 0 {
						t.Fatal("retained interval differs from H=3")
					}
					observedPrepare, observedCommit := new(big.Int), new(big.Int)
					for _, validator := range network.vals {
						counts, ok := recovered.RecentCounts(validator.Address)
						if !ok || counts.EligiblePrepare.Cmp(big.NewInt(3)) != 0 || counts.EligibleCommit.Cmp(big.NewInt(3)) != 0 || counts.ObservedPrepare.Cmp(big.NewInt(3)) > 0 || counts.ObservedCommit.Cmp(big.NewInt(3)) > 0 {
							t.Fatalf("retained counts: %+v", counts)
						}
						observedPrepare.Add(observedPrepare, counts.ObservedPrepare)
						observedCommit.Add(observedCommit, counts.ObservedCommit)
					}
					if observedPrepare.Cmp(big.NewInt(9)) < 0 || observedCommit.Cmp(big.NewInt(9)) < 0 {
						t.Fatal("normal quorum observations were lost")
					}
					witnessed, err := os.ReadFile(filepath.Join(network.homes[i], "consensus", "observation", "witness.rlp"))
					if err != nil {
						t.Fatal(err)
					}
					items, err := rlp.ListItems(witnessed)
					if err != nil || len(items) == 0 || uint64(len(items)) > uint64(policy.WitnessItems) || uint64(len(witnessed)) > policy.WitnessBytes {
						t.Fatalf("normal witness spool bounds: %v", err)
					}
					includedOlder := false
					for number := uint64(3); number <= 18; number++ {
						carrier := nd.App.BlockByNumber(number)
						observation, err := wire.Decode(carrier.Header.Extra, policy.Policy.Codec)
						if err != nil {
							t.Fatal(err)
						}
						for _, proof := range observation.Proofs {
							if age, ok := carrier.Header.Number.Sub(proof.Height); ok && age.CmpUint64(1) > 0 {
								includedOlder = true
							}
						}
					}
					if !includedOlder {
						t.Fatal("stored witnesses did not reach a later permitted carrier")
					}

				}
				if i > 0 && codec.BlockHash(h) != codec.BlockHash(closedNodes[0].App.BlockByNumber(18).Header) {
					t.Fatal("normal nodes disagree")
				}
			}
		})
	}
}
