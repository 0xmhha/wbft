package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// viewInput is a view of the vector format.
type viewInput struct {
	Sequence Dec `json:"sequence"`
	Round    Dec `json:"round"`
}

func (v viewInput) view() types.View {
	return types.View{Sequence: types.MustHeightFromBig(&v.Sequence.Int), Round: mustRound(&v.Round.Int)}
}

func mustRound(b *big.Int) types.Round {
	r, err := types.RoundFromBig(b)
	if err != nil {
		panic(err) // Dec is never negative
	}
	return r
}

func hCheckMessage(_ string, input json.RawMessage) (any, error) {
	var in struct {
		View        viewInput `json:"view"`
		State       string    `json:"state"`
		PriorRound  Dec       `json:"prior_round"`
		Code        Dec       `json:"code"`
		MessageView viewInput `json:"message_view"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	st, ok := consensus.ParseStateName(in.State)
	if !ok {
		return nil, fmt.Errorf("%w: state %q", errInput, in.State)
	}
	code, err := in.Code.Uint64Checked()
	if err != nil {
		return nil, err
	}
	c := consensus.CheckMessage(in.View.view(), st, mustRound(&in.PriorRound.Int), codec.Code(code), in.MessageView.view())
	return obj{"result": c.String()}, nil
}

func hIsJustified(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Proposal     Hex       `json:"proposal"`
		TargetView   viewInput `json:"target_view"`
		RoundChanges []struct {
			Source         Hex  `json:"source"`
			Sequence       Dec  `json:"sequence"`
			Round          Dec  `json:"round"`
			PreparedRound  *Dec `json:"prepared_round"`
			PreparedDigest Hex  `json:"prepared_digest"`
		} `json:"round_changes"`
		Prepares []struct {
			Source   Hex `json:"source"`
			Sequence Dec `json:"sequence"`
			Round    Dec `json:"round"`
			Digest   Hex `json:"digest"`
		} `json:"prepares"`
		Quorum Dec `json:"quorum"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	proposal, err := toHash(in.Proposal)
	if err != nil {
		return nil, err
	}
	q, err := in.Quorum.Uint64Checked()
	if err != nil || q > 1<<30 {
		return nil, fmt.Errorf("%w: quorum", errInput)
	}
	rcs := make([]consensus.RoundChangeSummary, len(in.RoundChanges))
	for i, rc := range in.RoundChanges {
		src, err := toAddress(rc.Source)
		if err != nil {
			return nil, err
		}
		d, err := toHash(rc.PreparedDigest)
		if err != nil {
			return nil, err
		}
		s := consensus.RoundChangeSummary{
			Source:         src,
			View:           viewInput{rc.Sequence, rc.Round}.view(),
			PreparedDigest: d,
		}
		if rc.PreparedRound != nil {
			r := mustRound(&rc.PreparedRound.Int)
			s.PreparedRound = &r
		}
		rcs[i] = s
	}
	ps := make([]consensus.PrepareSummary, len(in.Prepares))
	for i, p := range in.Prepares {
		src, err := toAddress(p.Source)
		if err != nil {
			return nil, err
		}
		d, err := toHash(p.Digest)
		if err != nil {
			return nil, err
		}
		ps[i] = consensus.PrepareSummary{Source: src, View: viewInput{p.Sequence, p.Round}.view(), Digest: d}
	}
	return obj{"justified": consensus.IsJustified(proposal, in.TargetView.view(), rcs, ps, int(q))}, nil
}

func hBuildWait(_ string, input json.RawMessage) (any, error) {
	var in struct {
		BlockPeriod Dec `json:"block_period"`
		HeadTime    Dec `json:"head_time"`
		Round       Dec `json:"round"`
		Now         Dec `json:"now"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	bp, err := in.BlockPeriod.Uint64Checked()
	if err != nil {
		return nil, err
	}
	ht, err := in.HeadTime.Uint64Checked()
	if err != nil {
		return nil, err
	}
	now, err := in.Now.Uint64Checked()
	if err != nil || now > 1<<63-1 {
		return nil, fmt.Errorf("%w: now", errInput)
	}
	w := consensus.BuildWait(ht, bp, mustRound(&in.Round.Int), int64(now))
	return obj{"wait": itoa64(int64(w))}, nil
}

// steps answers the steps handlers with the step driver. The driver has no
// frame stage here: cases whose verdict belongs to the transport adapter are
// answered "unsupported" and are decided by that adapter's own driver.
func steps(handler string) handler {
	return func(_ string, input json.RawMessage) (any, error) {
		out, err := stepdriver.Run(handler, input, stepdriver.Options{})
		if errors.Is(err, stepdriver.ErrUnsupported) {
			return nil, errUnsupported
		}
		return out, err
	}
}
