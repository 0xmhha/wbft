package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

type futureHeaderClock struct {
	runner.Clock
	at time.Time
}

func (c futureHeaderClock) Now() time.Time { return c.at }

type futureHeaderSigner struct{ key *ecdsa.PrivateKey }

func (s futureHeaderSigner) SignRandao(data []byte) ([]byte, error) {
	return ecdsa.SignData(data, s.key)
}

// An observer validates a normally constructed proposal on its public import
// service. The local clock and a normal configured transition select H2.
func TestFutureTimeAllowanceReachesNodeImport(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			key := testKey(0)
			raw, g := testGenesis(t, key)
			var config map[string]any
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			anzeon := config["anzeon"].(map[string]any)
			anzeon["wbft"].(map[string]any)["allowedFutureBlockTime"] = 1
			config["transitions"] = []any{map[string]any{"block": 1, "allowedFutureBlockTime": 2}}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := types.ParseChainConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			a := newTestApp(raw, g)
			parentState, err := a.Snapshot(context.Background(), codec.BlockHash(g.Header))
			if err != nil {
				t.Fatal(err)
			}
			private, err := ecdsa.PrivateKeyFromBytes(key)
			if err != nil {
				t.Fatal(err)
			}
			skeleton := &types.Header{ParentHash: codec.BlockHash(g.Header), Number: types.HeightFromUint64(1), UncleHash: types.EmptyUncleHash, Root: g.Header.Root, GasLimit: g.Header.GasLimit, BaseFee: g.Header.BaseFee}
			h, err := header.PrepareProposal(&header.Env{Config: cfg, Chain: a, Now: func() time.Time { return time.Unix(int64(g.Header.Time), 0) }}, skeleton, header.ProposalInputs{Coinbase: ecdsa.Address(private), Signer: futureHeaderSigner{private}, ParentGasTip: parentState.GasTip()})
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			if enabled {
				names = []string{"use_future_time_allowance"}
			}
			clock := futureHeaderClock{Clock: runner.SystemClock(), at: time.Unix(int64(g.Header.Time)-1, 250_000_000)}
			n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a, fs: fsys.NewMem(), clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			a.cons = n.Consensus()
			if err = n.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer stop(t, n)
			err = n.Consensus().VerifyHeader(context.Background(), h, app.VerifyOptions{CheckSeals: false})
			if enabled && err != nil || !enabled && !errors.Is(err, header.ErrFutureBlock) {
				t.Fatal("import did not use selected future allowance", err)
			}
		})
	}
}
