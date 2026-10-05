package node

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/types"
)

// chainView answers the runner's chain questions from the application's
// chain and the header rules. It implements runner.Chain.
type chainView struct {
	a     app.Application
	cfg   *types.Config
	snaps *source.Cache
	now   func() time.Time
	rej   *rejection.Store // the rejected proposals (wbft_rejections)
	log   *slog.Logger
	// misses counts the parent snapshots the header rules did not find
	// (wbft_authority_cache_misses_total); nil counts nothing.
	misses *metrics.Counter
}

var _ runner.Chain = (*chainView)(nil)

// env is the environment of the header rules; context names the
// verification for the cache miss counter (preprepare, header_only), and
// "" counts nothing (building, whose miss service.snapshot counts).
func (c *chainView) env(context string) *header.Env {
	return &header.Env{Config: c.cfg, Chain: c.a, BadBlock: c.a.IsBadBlock, PartB: c.a, Snapshots: c.snapshots(context), Now: c.now}
}

// snapshots is the snapshot cache as the header rules of one verification
// read it.
func (c *chainView) snapshots(context string) header.SnapshotReader {
	if c.misses == nil || context == "" {
		return c.snaps
	}
	return &countedSnaps{c: c.snaps, misses: c.misses, context: context}
}

// countedSnaps reads the snapshot cache for one verification and counts a
// missing parent once, though the header rules look it up at two steps
// (H15b, H21). VerifyHeaders reads it from its own goroutine.
type countedSnaps struct {
	c       *source.Cache
	misses  *metrics.Counter
	context string
	mu      sync.Mutex
	counted map[types.Hash]bool
}

func (s *countedSnaps) Get(hash types.Hash) (*source.AuthoritySnapshot, bool) {
	snap, ok := s.c.Get(hash)
	if ok && snap != nil {
		return snap, ok
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.counted[hash] {
		if s.counted == nil {
			s.counted = map[types.Hash]bool{}
		}
		s.counted[hash] = true
		s.misses.Inc(s.context)
	}
	return snap, ok
}

func (c *chainView) Head() *types.Header { return c.a.Head() }

func (c *chainView) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(c.a, c.cfg, n, parent, nil)
}

// ValidateProposal verifies a proposal and records a rejection; a proposal
// from the future is not rejected, the core waits for it.
func (c *chainView) ValidateProposal(b *types.Block) (time.Duration, error) {
	d, err := header.VerifyProposal(c.env("preprepare"), b)
	if err != nil && !errors.Is(err, header.ErrFutureBlock) && c.rej != nil {
		r := rejection.Record{Number: b.Header.Number.String(), Hash: "0x" + hex.EncodeToString(codec.BlockHash(b.Header).Bytes()),
			Path: "preprepare", Time: c.now()}
		var se *header.StepError
		if errors.As(err, &se) {
			r.Step, r.Class = se.Step, se.Class
		}
		if werr := c.rej.Add(r); werr != nil {
			c.log.Warn("rejection store write failed", "err", werr)
		}
	}
	return d, err
}

func (c *chainView) IsBadBlock(h types.Hash) bool { return c.a.IsBadBlock(h) }

// appDriver passes the runner's build requests and decided blocks to the
// application. It implements runner.App.
type appDriver struct {
	a   app.Application
	ctx context.Context
}

var _ runner.App = (*appDriver)(nil)

func (d *appDriver) ReadyToBuild(req consensus.RequestBuild, wait time.Duration, done <-chan struct{}) {
	// The core builds on the head of its last NewHead, which is the
	// application's head unless the head moved since.
	var parent types.Hash
	if h := d.a.Head(); h != nil && h.Number.AddUint64(1).Cmp(req.Height) == 0 {
		parent = codec.BlockHash(h)
	}
	d.a.ReadyToBuild(app.BuildRequest{Height: req.Height, Round: req.Round, Wait: wait, Parent: parent, Done: done})
}

func (d *appDriver) FinalizeBlock(b *types.Block, round types.Round) error {
	_, err := d.a.FinalizeBlock(d.ctx, app.FinalizeRequest{Block: b, Round: round})
	return err
}
