package main

import (
	"encoding/binary"
	"encoding/json"
	"math"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// Handlers of the runners "validators" (A-04) and "timers" (A-06).

func hQuorum(_ string, input json.RawMessage) (any, error) {
	var in struct {
		N Dec `json:"n"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	n64, err := in.N.Uint64Checked()
	if err != nil || n64 > math.MaxInt32 {
		return nil, errInput
	}
	n := int(n64)
	bits := make([]byte, 8)
	binary.BigEndian.PutUint64(bits, math.Float64bits(validator.FValue(n)))
	// The F+1 count is the one count in the binary64 window (below 2^53 + 2
	// there is exactly one; it is found next to the integer form).
	fp1 := validator.FPlusOneThreshold(n)
	for _, c := range []int{fp1, fp1 - 1, fp1 + 1} {
		if c >= 0 && validator.InFPlusOneWindow(c, n) {
			fp1 = c
			break
		}
	}
	return obj{
		"f_float64_bits": hexOut(bits),
		"quorum":         decOut(uint64(validator.QuorumSize(n))),
		"f_plus_one":     decOut(uint64(fp1)),
	}, nil
}

func hProposer(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Validators   []Hex `json:"validators"`
		Policy       Dec   `json:"policy"`
		LastProposer Hex   `json:"last_proposer"`
		Round        Dec   `json:"round"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	addrs := make([]types.Address, len(in.Validators))
	keys := make([][]byte, len(in.Validators))
	for i, v := range in.Validators {
		a, err := toAddress(v)
		if err != nil {
			return nil, err
		}
		addrs[i] = a
	}
	pol, err := in.Policy.Uint64Checked()
	if err != nil {
		return nil, err
	}
	last, err := toAddress(in.LastProposer)
	if err != nil {
		return nil, err
	}
	round, err := in.Round.Uint64Checked()
	if err != nil {
		return nil, err
	}
	vs, err := validator.NewSet(addrs, keys, types.ProposerPolicy{ID: pol})
	if err != nil {
		return nil, err
	}
	i := vs.CalcProposer(last, round)
	if i < 0 {
		return obj{"index": nil, "address": nil}, nil
	}
	// The index reported is that of the first member with the proposer's
	// address.
	first, _ := vs.IndexOf(vs.At(i).Addr)
	return obj{"index": decOut(uint64(first)), "address": addrOut(vs.At(i).Addr)}, nil
}

func hEpochBoundary(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Config pureConfig `json:"config"`
		Number Dec        `json:"number"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	cfg, err := in.Config.config()
	if err != nil {
		return nil, err
	}
	n, err := types.HeightFromBig(&in.Number.Int)
	if err != nil {
		return nil, err
	}
	is, err := validator.IsEpochBlock(cfg, n)
	if err != nil {
		return nil, err
	}
	last, err := validator.LastEpochBlock(cfg, n)
	if err != nil {
		return nil, err
	}
	return obj{"is_epoch_block": is, "last_epoch_block": last.String()}, nil
}

func hValidatorsAt(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Chain      fixtureIn `json:"chain"`
		Number     Dec       `json:"number"`
		ParentHash Hex       `json:"parent_hash"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	chain, cfg, _, err := in.Chain.build()
	if err != nil {
		return nil, err
	}
	n, err := types.HeightFromBig(&in.Number.Int)
	if err != nil {
		return nil, err
	}
	ph, err := toHash(in.ParentHash)
	if err != nil {
		return nil, err
	}
	vs, err := validator.ValidatorsAt(chain, cfg, n, ph, nil)
	if err != nil {
		return nil, err
	}
	list := make([]any, vs.Len())
	for i := range list {
		m := vs.At(i)
		list[i] = obj{"address": addrOut(m.Addr), "bls_public_key": hexOut(m.BLSPublicKey)}
	}
	return obj{"validators": list, "proposer_policy": decOut(vs.Policy().ID)}, nil
}

func hShuffle(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Seed    Hex   `json:"seed"`
		Count   Dec   `json:"count"`
		Indices []Dec `json:"indices"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	seed, err := toHash(in.Seed)
	if err != nil {
		return nil, err
	}
	count, err := in.Count.Uint64Checked()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(in.Indices))
	for i := range in.Indices {
		idx, err := in.Indices[i].Uint64Checked()
		if err != nil {
			return nil, err
		}
		j, err := epoch.ComputeShuffledIndex(idx, count, seed)
		if err != nil {
			return nil, err
		}
		out[i] = decOut(j)
	}
	return obj{"shuffled": out}, nil
}

func hSortCandidates(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Diligences []Dec `json:"diligences"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	cs := make([]epoch.ScoredCandidate, len(in.Diligences))
	for i := range in.Diligences {
		d, err := in.Diligences[i].Uint64Checked()
		if err != nil {
			return nil, err
		}
		cs[i] = epoch.ScoredCandidate{Power: 1, Diligence: d}
	}
	order := epoch.SortCandidates(cs)
	out := make([]any, len(order))
	for i, o := range order {
		out[i] = decOut(uint64(o))
	}
	return obj{"order": out}, nil
}

func hNextEpochInfo(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Chain      fixtureIn `json:"chain"`
		Header     Hex       `json:"header"`
		Candidates []struct {
			Address      Hex `json:"address"`
			BLSPublicKey Hex `json:"bls_public_key"`
		} `json:"candidates"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	chain, cfg, _, err := in.Chain.build()
	if err != nil {
		return nil, err
	}
	e, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	cands := make([]types.CandidateEntry, len(in.Candidates))
	for i, c := range in.Candidates {
		a, err := toAddress(c.Address)
		if err != nil {
			return nil, err
		}
		cands[i] = types.CandidateEntry{Addr: a, BLSPublicKey: c.BLSPublicKey}
	}
	ei, err := epoch.ComputeNextEpochInfo(chain, cfg, e, cands)
	if err != nil {
		return nil, err
	}
	if ei == nil {
		return obj{"epoch_info": nil}, nil
	}
	cl := make([]any, len(ei.Candidates))
	for i, c := range ei.Candidates {
		cl[i] = obj{"address": addrOut(c.Addr), "diligence": decOut(c.Diligence)}
	}
	vl := make([]any, len(ei.Validators))
	for i, v := range ei.Validators {
		vl[i] = decOut(uint64(v))
	}
	return obj{"epoch_info": obj{"candidates": cl, "validators": vl, "bls_public_keys": hexList(ei.BLSPublicKeys)}}, nil
}

func hRoundTimeout(_ string, input json.RawMessage) (any, error) {
	var in struct {
		RequestTimeout           Dec `json:"request_timeout"`
		MaxRequestTimeoutSeconds Dec `json:"max_request_timeout_seconds"`
		Round                    Dec `json:"round"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	rt, err := in.RequestTimeout.Uint64Checked()
	if err != nil {
		return nil, err
	}
	mx, err := in.MaxRequestTimeoutSeconds.Uint64Checked()
	if err != nil {
		return nil, err
	}
	r, err := types.RoundFromBig(&in.Round.Int)
	if err != nil {
		return nil, err
	}
	d, w := consensus.RoundTimeout(types.Params{RequestTimeoutMs: rt, MaxRequestTimeoutSeconds: mx}, r)
	return obj{"timeout": itoa64(int64(d)), "warning": w.String()}, nil
}
