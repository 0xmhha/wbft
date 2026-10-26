package kvstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/node"
	"github.com/0xmhha/wbft/types"
)

// A normal four-validator pair crosses activation and an epoch, then reopens.
func TestNormalBLSRandaoOffOnAndReopen(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			configure := func(g *Genesis) *node.ObservationConfig {
				if enabled {
					var raw map[string]json.RawMessage
					if err := json.Unmarshal(g.Config, &raw); err != nil {
						t.Fatal(err)
					}
					raw["wbftRules"] = json.RawMessage(`{"consensusRules":{"rejectNumberJump":0,"blsRandao":3}}`)
					var err error
					g.Config, err = json.Marshal(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			net := newTestNetConfigured(t, 4, configure, true)
			original := bytes.Clone(net.g.Config)
			owner := types.Address{0xd1}
			submit(t, net.nodes[0], Tx{From: owner, Nonce: 0, Key: "bls-reveal", Value: "before"})
			wait := func(target uint64, nonce uint64) {
				waitFor(t, "normal BLS reveal progress", 60*time.Second, func() bool {
					for _, nd := range net.nodes {
						if nd.App.Head().Number.CmpUint64(target) < 0 || nd.App.Nonce(owner) != nonce {
							return false
						}
					}
					return true
				})
			}
			wait(8, 1)
			var hashes []types.Hash
			for number := uint64(1); number <= 8; number++ {
				h := net.nodes[0].App.HeaderByNumber(number)
				hashes = append(hashes, codec.BlockHash(h))
				x, err := codec.DecodeExtra(h)
				want := 65
				if enabled && number >= 3 {
					want = 96
				}
				if err != nil || len(x.RandaoReveal) != want {
					t.Fatal("normal reveal format", number, err)
				}
				for _, nd := range net.nodes {
					if codec.BlockHash(nd.App.HeaderByNumber(number)) != codec.BlockHash(h) {
						t.Fatal("normal node hash differs", number)
					}
				}
			}
			for i, nd := range net.nodes {
				net.nodes[i] = nil
				if err := nd.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			for i := range net.nodes {
				net.open(i)
			}
			for i := range net.nodes {
				net.start(i)
			}
			submit(t, net.nodes[0], Tx{From: owner, Nonce: 1, Key: "bls-reveal", Value: "after"})
			wait(11, 2)
			for _, nd := range net.nodes {
				for i, want := range hashes {
					if codec.BlockHash(nd.App.HeaderByNumber(uint64(i+1))) != want {
						t.Fatal("stored pre-reopen hash changed")
					}
				}
				if value, ok := nd.App.Get("bls-reveal"); !ok || value != "after" {
					t.Fatal("normal reopened state differs")
				}
			}
			if !bytes.Equal(net.g.Config, original) {
				t.Fatal("original chain configuration rewritten")
			}
		})
	}
}
