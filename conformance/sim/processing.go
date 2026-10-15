package sim

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
)

// ProcessingProfile assigns service samples to explicit work classes. The
// existing operation executes atomically after service; internal CPU, WAL and
// output milestones are not reconstructed. Unlisted classes retain zero cost.
type ProcessingProfile struct {
	Workers int
	Costs   []ProcessingCost
}

type ProcessingCost struct {
	Phase   string
	Kind    string
	Code    uint64
	Samples []time.Duration
}

func cloneProcessing(p *ProcessingProfile, horizon time.Duration) (*ProcessingProfile, error) {
	if p == nil {
		return nil, nil
	}
	if p.Workers < 1 || p.Workers > 256 || len(p.Costs) == 0 || len(p.Costs) > 128 {
		return nil, fmt.Errorf("%w: invalid processing profile dimensions", ErrScenario)
	}
	out := &ProcessingProfile{Workers: p.Workers, Costs: make([]ProcessingCost, len(p.Costs))}
	seen := map[runner.ProcessingWork]bool{}
	for i, c := range p.Costs {
		work := runner.ProcessingWork{Phase: c.Phase, Kind: c.Kind, Code: c.Code}
		valid := false
		if c.Kind == inputlog.KindMessage {
			valid = c.Code == uint64(codec.CodePreprepare) || c.Code == uint64(codec.CodePrepare) || c.Code == uint64(codec.CodeCommit) || c.Code == uint64(codec.CodeRoundChange)
		} else if c.Code == 0 && c.Phase == runner.ProcessingCore {
			switch c.Kind {
			case inputlog.KindRequest, inputlog.KindNewHead, inputlog.KindBacklog, inputlog.KindTimeout, inputlog.KindCommitResult, inputlog.KindBroadcastFailed, inputlog.KindPeerConnected:
				valid = true
			}
		}
		if !valid || c.Phase != runner.ProcessingCheck && c.Phase != runner.ProcessingCore || seen[work] || len(c.Samples) == 0 || len(c.Samples) > 10000 {
			return nil, fmt.Errorf("%w: invalid processing work class", ErrScenario)
		}
		seen[work] = true
		for _, d := range c.Samples {
			if d < 0 || d > horizon {
				return nil, fmt.Errorf("%w: processing sample outside horizon", ErrScenario)
			}
		}
		out.Costs[i] = c
		out.Costs[i].Samples = slices.Clone(c.Samples)
	}
	return out, nil
}

func (n *node) processingModel() (*runner.ManualProcessing, int) {
	p := n.spec.Processing
	if p == nil {
		return nil, 0
	}
	costs := map[runner.ProcessingWork][]time.Duration{}
	positive := false
	for _, c := range p.Costs {
		costs[runner.ProcessingWork{Phase: c.Phase, Kind: c.Kind, Code: c.Code}] = c.Samples
		for _, d := range c.Samples {
			positive = positive || d > 0
		}
	}
	if !positive {
		return nil, 0
	}
	clock := n.clock
	return &runner.ManualProcessing{Delay: func(work runner.ProcessingWork) time.Duration {
		samples := costs[work]
		if len(samples) == 0 {
			return 0
		}
		if len(samples) == 1 {
			return samples[0]
		}
		return samples[n.rng.IntN(len(samples))]
	}, Schedule: func(d time.Duration, complete func()) {
		if d > n.s.sc.Until.Duration-n.s.l.c.Mono() {
			// Work extending beyond the capture horizon stays incomplete.
			return
		}
		clock.AfterFunc(d, func() { n.guard(complete) })
	}}, p.Workers
}

func processingDeclaration(p *ProcessingProfile) map[string]any {
	costs := make([]map[string]any, 0, len(p.Costs))
	for _, c := range p.Costs {
		samples := make([]string, len(c.Samples))
		for i, d := range c.Samples {
			samples[i] = strconv.FormatInt(int64(d), 10)
		}
		costs = append(costs, map[string]any{"phase": c.Phase, "kind": c.Kind, "code": c.Code, "samples_ns": samples})
	}
	return map[string]any{"policy": "pre_dispatch_service/1", "workers": p.Workers, "unlisted_classes": "zero_cost", "costs": costs}
}
