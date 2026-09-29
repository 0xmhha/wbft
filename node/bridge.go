package node

import (
	"context"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/types"
)

// chainView answers the runner's chain questions from the application's
// chain and the header rules. It implements runner.Chain.
type chainView struct {
	a     app.Application
	cfg   *types.Config
	snaps *source.Cache
	now   func() time.Time
}

var _ runner.Chain = (*chainView)(nil)

// env is the environment of the header rules.
func (c *chainView) env() *header.Env {
	return &header.Env{Config: c.cfg, Chain: c.a, BadBlock: c.a.IsBadBlock, PartB: c.a, Snapshots: c.snaps, Now: c.now}
}

func (c *chainView) Head() *types.Header { return c.a.Head() }

func (c *chainView) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(c.a, c.cfg, n, parent, nil)
}

func (c *chainView) ValidateProposal(b *types.Block) (time.Duration, error) {
	return header.VerifyProposal(c.env(), b)
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
