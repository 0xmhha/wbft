package stepdriver

import (
	"bytes"
	"math"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// Application results remain recorded observations. An experiment may reuse
// them only when the actual output reserves the same application question.
type timedBuild struct {
	request consensus.RequestBuild
	ready   int64
	known   bool
}
type timedApplicationLedger struct {
	builds  []timedBuild
	commits map[types.Hash]uint64
}

func sameBuild(a, b consensus.RequestBuild) bool {
	x, e := inputlog.EncodeOutputs([]consensus.Output{a})
	if e != nil {
		return false
	}
	y, e := inputlog.EncodeOutputs([]consensus.Output{b})
	return e == nil && bytes.Equal(x, y)
}
func (l *timedApplicationLedger) produced(actual, recorded []consensus.Output, baseline bool, now int64) error {
	for _, output := range actual {
		switch o := output.(type) {
		case consensus.RequestBuild:
			if len(l.builds) >= MaxReservedInputs {
				return ErrTraceAnswerLimit
			}
			known := baseline
			for _, original := range recorded {
				if b, ok := original.(consensus.RequestBuild); ok && sameBuild(o, b) {
					known = true
					break
				}
			}
			wait := int64(o.Wait(now))
			if wait > 0 && now > math.MaxInt64-wait {
				return ErrTraceTiming
			}
			l.builds = append(l.builds, timedBuild{o, now + wait, known})
		case consensus.Commit:
			if o.Block == nil || o.Block.Header == nil {
				return ErrTraceInvalidInput
			}
			known := baseline
			hash := codec.BlockHash(o.Block.Header)
			for _, original := range recorded {
				if c, ok := original.(consensus.Commit); ok && c.Block != nil && c.Block.Header != nil && codec.BlockHash(c.Block.Header) == hash {
					known = true
					break
				}
			}
			if !known {
				continue
			}
			if l.commits == nil {
				l.commits = map[types.Hash]uint64{}
			}
			if len(l.commits) >= MaxReservedInputs {
				return ErrTraceAnswerLimit
			}
			l.commits[hash]++
		}
	}
	return nil
}
func (l *timedApplicationLedger) allowed(in consensus.Input, via string, head *types.Header, now int64) error {
	if via != "app" {
		return nil
	}
	switch v := in.(type) {
	case consensus.Request:
		if v.Block == nil || v.Block.Header == nil || head == nil {
			return ErrTraceInvalidInput
		}
		h := v.Block.Header
		if h.ParentHash != codec.BlockHash(head) || h.Number.Cmp(head.Number.AddUint64(1)) != 0 {
			return ErrTraceEnvExhausted
		}
		for i, b := range l.builds {
			if b.known && b.ready <= now && b.request.Height.Cmp(h.Number) == 0 && b.request.HeadTime == head.Time {
				l.builds = append(l.builds[:i], l.builds[i+1:]...)
				return nil
			}
		}
		return ErrTraceEnvExhausted
	case consensus.CommitResult:
		if l.commits[v.Hash] == 0 {
			return ErrTraceEnvExhausted
		}
		l.commits[v.Hash]--
		if l.commits[v.Hash] == 0 {
			delete(l.commits, v.Hash)
		}
	}
	return nil
}
