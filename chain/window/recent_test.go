package window_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestRecentNormalWindowsAndSnapshotReplacement(t *testing.T) {
	for _, h := range []uint64{1, 3, 7, 64} {
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			c := normalRetention(t, 4, types.HeightFromUint64(1), true, types.HeightFromUint64(h), 36)
			provider, err := state.NewBranchHistory(c.engine, &hashStore{headers: c.history.headers}, consensusConfig(), 6)
			must(t, err)
			for n := 1; n < len(c.headers); n++ {
				_, err = c.engine.VerifyAndApply(c.states[n-1], c.headers[n], provider)
				must(t, err)
				x, err := wire.Decode(c.headers[n].Extra, c.history.limits)
				must(t, err)
				if x.Observation.Version != 2 || x.Observation.Settlement != nil {
					t.Fatal("recent format confused with cumulative delta")
				}
				if n%6 == 0 {
					r := x.Observation.Recent
					if r == nil || r.Through.Cmp(c.states[n-1].MaturedThrough()) != 0 {
						t.Fatal("settlement included current carrier maturity")
					}
					from, through, ok := c.states[n].SettledWindow()
					if !ok || from.Cmp(r.From) != 0 || through.Cmp(r.Through) != 0 {
						t.Fatal("snapshot range")
					}
				} else if x.Observation.Recent != nil {
					t.Fatal("non-epoch settlement")
				}
				cp, err := c.engine.EncodeCheckpoint(c.states[n], c.headers[n])
				must(t, err)
				items, err := rlp.ListItems(cp)
				must(t, err)
				data, err := rlp.ListItems(items[3])
				must(t, err)
				if len(data) != 10 {
					t.Fatal("recent state schema")
				}
				retained, err := rlp.ListItems(data[8])
				must(t, err)
				if uint64(len(retained)) > h {
					t.Fatal("unbounded matured history")
				}
				for _, target := range retained {
					fields, err := rlp.ListItems(target)
					must(t, err)
					if len(fields) != 4 {
						t.Fatal("retained historical keys or certificates")
					}
				}
				restored, err := c.engine.Recover(cp, c.headers[n])
				must(t, err)
				root, err := c.engine.Root(restored)
				must(t, err)
				want, err := c.engine.Root(c.states[n])
				must(t, err)
				if root != want {
					t.Fatal("checkpoint root")
				}
			}
		})
	}
}
func TestRecentRejoiningAddressReceivesNoOldHistory(t *testing.T) {
	c := normalRetention(t, 4, types.HeightFromUint64(1), true, types.HeightFromUint64(3), 36)
	if _, ok := c.states[16].RecentCounts(address(1)); ok {
		t.Fatal("departed signer retained expired history")
	}
	got, ok := c.states[17].RecentCounts(address(1))
	if !ok || got.EligiblePrepare.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("rejoining signer inherited old opportunities")
	}
	got, ok = c.states[18].Counts(address(1))
	if !ok || got.EligiblePrepare.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("settled rejoin window")
	}
	if _, ok = c.states[30].Counts(address(5)); ok {
		t.Fatal("expired settled address retained forever")
	}
	if output := os.Getenv("WBFT_RECENT_FIXTURE_OUTPUT"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		h := c.headers[24]
		raw, err := codec.EncodeHeader(h)
		must(t, err)
		hash, err := wire.BlockHash(h, c.history.limits)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(output, "recent-header.rlp"), raw, 0600))
		meta, err := json.MarshalIndent(map[string]any{"block_hash": hex.EncodeToString(hash[:]), "height": 24, "H": 3, "carrier_window": 4, "settled_from": 17, "settled_through": 19, "description": "Offline normal carrier with complete recent-window settlement; no network activation or timing attestation."}, "", "  ")
		must(t, err)
		must(t, os.WriteFile(filepath.Join(output, "recent-header.json"), meta, 0600))
	}

}
func TestRecentPolicyAndClosedCheckpointSeparation(t *testing.T) {
	_, _, hist, parent := initial(t, 4, types.HeightFromUint64(1))
	cfg := state.Config{ChainID: big.NewInt(88001), GenesisHash: parentHash(t, hist, parent), Activation: types.HeightFromUint64(1), Window: 4, Codec: hist.limits, StateBytes: 65536, CheckpointBytes: 131072, AddressRows: 32}
	if _, err := state.NewRecent(cfg, types.Height{}); err == nil {
		t.Fatal("implicit H")
	}
	old, err := state.New(cfg)
	must(t, err)
	a, err := state.NewRecent(cfg, types.HeightFromUint64(3))
	must(t, err)
	b, err := state.NewRecent(cfg, types.HeightFromUint64(4))
	must(t, err)
	if old.Digest() == a.Digest() || a.Digest() == b.Digest() {
		t.Fatal("retention not policy bound")
	}
	recent := normalRetention(t, 4, types.HeightFromUint64(1), true, types.HeightFromUint64(3), 24)
	legacy := normal(t, 4, types.HeightFromUint64(1))
	cp, err := recent.engine.EncodeCheckpoint(recent.states[24], recent.headers[24])
	must(t, err)
	if _, err = legacy.engine.Recover(cp, recent.headers[24]); err == nil {
		t.Fatal("recent checkpoint accepted by cumulative engine")
	}
	original, err := recent.engine.Root(recent.states[23])
	must(t, err)
	x, err := wire.Decode(recent.headers[24].Extra, recent.history.limits)
	must(t, err)
	x.Observation.Recent.From = x.Observation.Recent.From.AddUint64(1)
	// Diagnose a closed copied commitment. No changed header reaches an actor.
	copied := recent.headers[24].Copy()
	copied.Extra, err = wire.Encode(x, recent.history.limits)
	if err == nil {
		if _, err = recent.engine.Apply(recent.states[23], copied, recent.history); err == nil {
			t.Fatal("copied window accepted")
		}
	}
	after, err := recent.engine.Root(recent.states[23])
	must(t, err)
	if !bytes.Equal(original[:], after[:]) {
		t.Fatal("failed transition changed parent")
	}
}
func parentHash(t *testing.T, hist *history, parent *types.Header) types.Hash {
	t.Helper()
	hash, err := hist.hash(parent)
	must(t, err)
	return hash
}
func TestRecentFullHeightWindowArithmetic(t *testing.T) {
	high := types.MustHeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(9)))
	normalRetention(t, 4, high, false, types.HeightFromUint64(3), 24)
	enormous := types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 128))
	normalRetention(t, 4, types.HeightFromUint64(1), false, enormous, 24)
}
