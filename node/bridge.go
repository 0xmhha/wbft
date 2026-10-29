package node

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/types"
)

// chainView answers the runner's chain questions from the application's
// chain and the header rules. It implements runner.Chain.
type chainView struct {
	observation *observationRuntime
	a           app.Application
	cfg         *types.Config
	snaps       *source.Cache
	now         func() time.Time
	rej         *rejection.Store // the rejected proposals (wbft_rejections)
	log         *slog.Logger
	// misses counts the parent snapshots the header rules did not find
	// (wbft_authority_cache_misses_total); nil counts nothing.
	misses *metrics.Counter
	// emit writes a record to the node's event stream; nil drops it.
	emit                   func(event.Record)
	futureTimeAllowance    bool
	checkEpochInfoPresence bool
}

var _ runner.Chain = (*chainView)(nil)

// env is the environment of the header rules; context names the
// verification for the cache miss counter (preprepare, header_only), and
// "" counts nothing (building, whose miss service.snapshot counts).
func (c *chainView) env(context string) *header.Env {
	env := &header.Env{Config: c.cfg, Chain: c.a, BadBlock: c.a.IsBadBlock, PartB: c.a, Snapshots: c.snapshots(context), Now: c.now, UseFutureTimeAllowance: c.futureTimeAllowance, CheckEpochInfoPresence: c.checkEpochInfoPresence}
	if c.observation != nil {
		env.Observation = c.observation
	}
	return env
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
	return c.validateProposal(b, "preprepare")
}

// ValidateRoundProposal checks a local prepared candidate without claiming
// that a PRE-PREPARE was received from a peer.
func (c *chainView) ValidateRoundProposal(b *types.Block) (time.Duration, error) {
	return c.validateProposal(b, "local_reproposal")
}

func (c *chainView) validateProposal(b *types.Block, path string) (time.Duration, error) {
	d, err := header.VerifyProposal(c.env(path), b)
	if errors.Is(err, header.ErrSnapshotMissing) && c.emit != nil {
		// The core sends no PREPARE for it and does not wait
		// (app-interface.md 5.4): the application stored the parent
		// before its snapshot.
		c.emit(event.Record{Kind: event.Health, Fields: map[string]any{"what": "snapshot_missing_at_" + path,
			"h": b.Header.Number.String(), "hash": "0x" + hex.EncodeToString(codec.BlockHash(b.Header).Bytes()),
			"parent": "0x" + hex.EncodeToString(b.Header.ParentHash.Bytes())}})
	}
	if err != nil && !errors.Is(err, header.ErrFutureBlock) && c.rej != nil {
		r := rejection.Record{Number: b.Header.Number.String(), Hash: "0x" + hex.EncodeToString(codec.BlockHash(b.Header).Bytes()),
			Path: path, Time: c.now()}
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
	// failed, when set, is told a decided block the application failed to
	// import (an *app.ImportError from FinalizeBlock); the node records it
	// as for OnImportFailed.
	failed           func(app.ImportFailure)
	emit             func(event.Record)
	buildIDs         *atomic.Uint64
	diagnostic       *sessionFrameRecorder
	applicationBytes uint64
}

var _ runner.App = (*appDriver)(nil)

func (d *appDriver) ReadyToBuild(req consensus.RequestBuild, wait time.Duration, done <-chan struct{}) {
	// The core builds on the head of its last NewHead, which is the
	// application's head unless the head moved since.
	var parent types.Hash
	if h := d.a.Head(); h != nil && h.Number.AddUint64(1).Cmp(req.Height) == 0 {
		parent = codec.BlockHash(h)
	}
	var observation *app.BuildObservation
	if d.emit != nil && d.buildIDs != nil {
		id := fmt.Sprintf("build-%d", d.buildIDs.Add(1))
		view := types.View{Sequence: req.Height, Round: req.Round}
		d.emit(event.Record{Kind: event.BuildHandover, View: event.ViewOf(view), Fields: map[string]any{
			"build_id": id, "number": req.Height.String(), "wait_ns": fmt.Sprint(int64(wait)), "parent": parent.Hex()}})
		observation = app.NewBuildObservation(func(phase app.BuildPhase, status app.BuildStatus, hash types.Hash) {
			fields := map[string]any{"build_id": id, "number": req.Height.String()}
			kind := event.BuildStarted
			if phase == app.BuildCompleted {
				kind = event.BuildFinished
				fields["status"] = string(status)
				if status == app.BuildSubmitted {
					fields["hash"] = hash.Hex()
				}
			}
			d.emit(event.Record{Kind: kind, View: event.ViewOf(view), Fields: fields})
		})
	}
	d.a.ReadyToBuild(app.BuildRequest{Height: req.Height, Round: req.Round, Wait: wait, Parent: parent, Done: done, Observation: observation})
}

func (d *appDriver) FinalizeBlock(b *types.Block, round types.Round) error {
	return d.finalize(app.FinalizeRequest{Block: b, Round: round})
}

func (d *appDriver) FinalizeBlockWithSource(b *types.Block, round types.Round, source app.FinalizeSource) error {
	return d.finalize(app.FinalizeRequest{Block: b, Round: round, Source: &source})
}

func (d *appDriver) finalize(req app.FinalizeRequest) error {
	b := req.Block
	var source *journal.ApplicationRec
	if d.diagnostic != nil {
		source = d.diagnostic.beginApplication(req, d.applicationBytes)
	}
	response, err := d.a.FinalizeBlock(d.ctx, req)
	if source != nil {
		d.diagnostic.finishApplication(source, response, err)
	}
	if ie := (*app.ImportError)(nil); d.failed != nil && errors.As(err, &ie) {
		// An invalid block is recorded as bad by the application
		// (WBFT-APP-090); another import failure is not.
		d.failed(app.ImportFailure{Number: b.Header.Number, Hash: codec.BlockHash(b.Header), Path: app.SealedLocally,
			RecordedBad: errors.Is(err, app.ErrInvalidBlock), Err: ie})
	}
	return err
}

// buildEventEmitter binds asynchronous callbacks to the writer and clock of
// their original node run. A later Start cannot move a completion to a new run.
func (n *Node) buildEventEmitter() func(event.Record) {
	writer, clock, log := n.ev, n.clock, n.log
	return func(record event.Record) {
		if writer == nil {
			return
		}
		if err := writer.Write(record, event.Stamp{Wall: clock.Now(), Mono: clock.Mono()}); err != nil && log != nil {
			log.Warn("build event write failed", "err", err)
		}
	}
}
