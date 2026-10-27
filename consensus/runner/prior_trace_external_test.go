package runner_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type priorTraceClock struct{}
type priorTraceTimer struct{}

func (priorTraceClock) Now() time.Time                               { return time.Unix(1700000011, 0) }
func (priorTraceClock) Mono() time.Duration                          { return 0 }
func (priorTraceClock) AfterFunc(time.Duration, func()) runner.Timer { return priorTraceTimer{} }
func (priorTraceTimer) Stop() bool                                   { return true }

type priorTraceApp struct{}

type priorTraceObserver struct {
	writer journal.Writer
	run    string
}

func (o *priorTraceObserver) CaptureRun() string { return o.run }
func (o *priorTraceObserver) ObserveWALRead(r journal.WALReadRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *priorTraceObserver) ObserveRestore(r journal.RestoreRec) {
	o.writer.Put(journal.Record{Body: &r})
}

func (priorTraceApp) ReadyToBuild(consensus.RequestBuild, time.Duration, <-chan struct{}) {}
func (priorTraceApp) FinalizeBlock(*types.Block, types.Round) error {
	return errors.New("observer test does not execute blocks")
}

type priorTraceChain struct {
	head        *types.Header
	blocks      map[types.Hash]*types.Block
	byNumber    map[string]*types.Header
	past, next  *validator.Set
	unavailable bool
}

func (c *priorTraceChain) Head() *types.Header { return c.head }
func (c *priorTraceChain) HeaderByNumber(n types.Height) (*types.Header, error) {
	h := c.byNumber[n.String()]
	if h == nil {
		return nil, errors.New("header unavailable")
	}
	return h, nil
}
func (c *priorTraceChain) BlockByHash(h types.Hash) (*types.Block, error) {
	b := c.blocks[h]
	if b == nil {
		return nil, errors.New("block unavailable")
	}
	return b, nil
}
func (c *priorTraceChain) ValidatorsAt(n types.Height, p types.Hash) (*validator.Set, error) {
	if n.Cmp(c.head.Number) == 0 && p == c.head.ParentHash {
		if c.unavailable {
			return nil, errors.New("normal historical lookup unavailable")
		}
		return c.past, nil
	}
	if n.Cmp(c.head.Number.AddUint64(1)) == 0 && p == codec.BlockHash(c.head) {
		return c.next, nil
	}
	return nil, errors.New("query outside retained context")
}
func (*priorTraceChain) ValidateProposal(*types.Block) (time.Duration, error) { return 0, nil }
func (*priorTraceChain) IsBadBlock(types.Hash) bool                           { return false }

func TestPriorHeadJournalClosedReplay(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		for _, deferred := range []bool{false, true} {
			t.Run(fmt.Sprintf("unavailable%t/deferred%t", unavailable, deferred), func(t *testing.T) {
				var addresses []types.Address
				var keys [][]byte
				var secrets []*bls.SecretKey
				for i := 0; i < 4; i++ {
					raw := keccak.Sum256Bytes([]byte(fmt.Sprintf("prior-normal-key-%d", i)))
					e, err := ecdsa.PrivateKeyFromBytes(raw)
					if err != nil {
						t.Fatal(err)
					}
					b, err := bls.DeriveSecretKey(raw)
					if err != nil {
						t.Fatal(err)
					}
					addresses = append(addresses, ecdsa.Address(e))
					keys = append(keys, b.PublicKey().Bytes())
					secrets = append(secrets, b)
				}
				past, err := validator.NewSet(addresses, keys, types.ProposerPolicy{})
				if err != nil {
					t.Fatal(err)
				}
				next, err := validator.NewSet(addresses[1:], keys[1:], types.ProposerPolicy{})
				if err != nil {
					t.Fatal(err)
				}
				newBlock := func(n uint64, parent types.Hash) *types.Block {
					x, err := codec.EncodeExtra(&types.WBFTExtra{VanityData: make([]byte, types.ExtraVanity), RandaoReveal: []byte{}})
					if err != nil {
						t.Fatal(err)
					}
					return &types.Block{Header: &types.Header{ParentHash: parent, Number: types.HeightFromUint64(n), Coinbase: addresses[0], UncleHash: types.EmptyUncleHash, Difficulty: big.NewInt(1), GasLimit: 30000000, Time: 1700000000 + n, Extra: x}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
				}
				parent := newBlock(9, types.Hash{8})
				b := newBlock(10, codec.BlockHash(parent.Header))
				var prepares, commits []types.SealEntry
				for i := 0; i < 3; i++ {
					prepares = append(prepares, types.SealEntry{Sealer: uint32(i), Seal: secrets[i].Sign(codec.SealData(b.Header, 0, types.PrepareSeal)).Bytes()})
					commits = append(commits, types.SealEntry{Sealer: uint32(i), Seal: secrets[i].Sign(codec.SealData(b.Header, 0, types.CommitSeal)).Bytes()})
				}
				sealed, err := header.CommitHeader(b, types.Round{}, prepares, commits)
				if err != nil {
					t.Fatal(err)
				}
				proposal := newBlock(11, codec.BlockHash(sealed.Header))
				chain := &priorTraceChain{head: sealed.Header, blocks: map[types.Hash]*types.Block{}, byNumber: map[string]*types.Header{}, past: past, next: next, unavailable: unavailable}
				for _, block := range []*types.Block{parent, sealed, proposal} {
					chain.blocks[codec.BlockHash(block.Header)] = block
					chain.byNumber[block.Header.Number.String()] = block.Header
				}
				raw := []byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":1099511627776,"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"proposerPolicy":0}}}`)
				options := journal.CoreOptions{ChainConfig: raw, Improvements: uint64(consensus.ImprovementSet(0).With(consensus.BindPriorHead))}
				if deferred {
					options.NextHeight = &journal.DeferredOptions{Profile: journal.DeferredInputProfile, Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}
				}
				cfg, err := options.Configuration()
				if err != nil {
					t.Fatal(err)
				}
				fs := fsys.NewMem()
				for startup := 0; startup < 2; startup++ {
					jw, err := journal.Open(journal.Options{FS: fs, Dir: "/journal", Synchronous: true}, journal.Identity{Run: fmt.Sprintf("prior-normal-start-%d", startup), Core: options})
					if err != nil {
						t.Fatal(err)
					}
					log, _, err := wal.Open(fs, "/wal", wal.Options{SegmentBytes: 4096, KeepHeights: 2})
					if err != nil {
						t.Fatal(err)
					}
					config := runner.Config{Core: consensus.Options{Config: cfg, Improvements: consensus.ImprovementSet(options.Improvements)}, ReplayWAL: true, Manual: true}
					if deferred {
						config.NextHeight = &runner.NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}
					}
					observer := &priorTraceObserver{writer: jw, run: fmt.Sprintf("prior-normal-start-%d", startup)}
					r, err := runner.New(config, runner.Deps{Chain: chain, App: priorTraceApp{}, Clock: priorTraceClock{}, WAL: log, Journal: jw, WALReadSources: observer, WALReadSourceLimits: wal.ReadSourceLimits{Frames: 1024, Bytes: 8 << 20}, Rand: func(int) int { return 0 }})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = r.Close(); _ = log.Close(); _ = jw.Close() })
					if err = r.Start(context.Background(), types.HeightFromUint64(11)); err != nil {
						t.Fatal(err)
					}
					if startup == 0 {
						r.Submit(proposal)
						r.Pump()
					} else if !r.LastReplay().Replayed {
						t.Fatal("normal restart did not replay")
					}
					if err = r.Close(); err != nil {
						t.Fatal(err)
					}
					if err = log.Close(); err != nil {
						t.Fatal(err)
					}
					if err = jw.Close(); err != nil {
						t.Fatal(err)
					}
				}
				open := func() *journal.Reader {
					rd, err := journal.OpenReader(fs, "/journal")
					if err != nil {
						t.Fatal(err)
					}
					return rd
				}
				records, err := journal.ReadAll(fs, "/journal")
				if err != nil {
					t.Fatal(err)
				}
				proof, err := journal.CheckRestoreSources(records, journal.CoreSourceLimits{Records: 4096, Runs: 16, Steps: 4096, Environments: 4096, Outputs: 16384, Bytes: 32 << 20})
				if deferred {
					if err != nil || proof.Status != "unavailable" || proof.Reason != "restore_next_height" {
						t.Fatal("deferred independent ledger support must remain explicit", proof, err)
					}
				} else if err != nil || proof.Status != "consistent" || proof.Attempts == 0 || proof.Inputs == 0 {
					t.Fatal("independent ordinary prior-source restore incomplete", proof, err)
				}
				for _, scoped := range []bool{false, true} {
					opts := stepdriver.TraceOptions{Blocks: chain, WithVars: true}
					if scoped {
						pool, err := stepdriver.NewAnswerPool(open())
						if err != nil {
							t.Fatal(err)
						}
						opts.Answers = pool
						opts.AnswerScope = "context"
					}
					steps, authority := 0, 0
					err := stepdriver.RunTrace(open(), opts, func(step stepdriver.StepResult) error {
						steps++
						if !step.Match {
							t.Errorf("closed replay mismatch at %s/%d/%d", step.WriterRun, step.EngineRun, step.Step)
						}
						for _, call := range step.EnvCalls {
							if call.Kind == inputlog.EnvValidatorsAt {
								authority++
							}
						}
						return nil
					})
					if err != nil || steps == 0 || authority < 4 {
						t.Fatal("recorded authority replay incomplete", steps, authority, err)
					}
				}
			})
		}
	}
}
