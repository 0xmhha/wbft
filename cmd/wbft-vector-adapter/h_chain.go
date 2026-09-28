package main

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/snetpartb"
	"github.com/0xmhha/wbft/types"
)

// The configuration and chain fixture of A-11 §3.1 ("Chain fixture").

// wbftSection is anzeon.wbft or the WBFT part of a transition, in snake case.
type wbftSection struct {
	RequestTimeoutSeconds    Dec  `json:"request_timeout_seconds"`
	BlockPeriodSeconds       Dec  `json:"block_period_seconds"`
	EpochLength              Dec  `json:"epoch_length"`
	AllowedFutureBlockTime   Dec  `json:"allowed_future_block_time"`
	ProposerPolicy           *Dec `json:"proposer_policy"`
	MaxRequestTimeoutSeconds *Dec `json:"max_request_timeout_seconds"`
}

func (w *wbftSection) params() (types.WBFTParams, error) {
	var p types.WBFTParams
	var err error
	for _, f := range []struct {
		d   *Dec
		dst *uint64
	}{
		{&w.RequestTimeoutSeconds, &p.RequestTimeoutSeconds},
		{&w.BlockPeriodSeconds, &p.BlockPeriodSeconds},
		{&w.EpochLength, &p.EpochLength},
		{&w.AllowedFutureBlockTime, &p.AllowedFutureBlockTime},
	} {
		if *f.dst, err = f.d.Uint64Checked(); err != nil {
			return p, err
		}
	}
	if w.ProposerPolicy != nil {
		v, err := w.ProposerPolicy.Uint64Checked()
		if err != nil {
			return p, err
		}
		p.ProposerPolicy = &v
	}
	if w.MaxRequestTimeoutSeconds != nil {
		v, err := w.MaxRequestTimeoutSeconds.Uint64Checked()
		if err != nil {
			return p, err
		}
		p.MaxRequestTimeoutSeconds = &v
	}
	return p, nil
}

type transitionIn struct {
	Block Dec `json:"block"`
	wbftSection
}

// pureConfig is the "config" input of chain/config_at and
// validators/epoch_boundary.
type pureConfig struct {
	WBFT        wbftSection    `json:"wbft"`
	Transitions []transitionIn `json:"transitions"`
}

func buildConfig(w *wbftSection, ts []transitionIn, init types.GenesisInit, chainID *big.Int) (*types.Config, error) {
	base, err := w.params()
	if err != nil {
		return nil, err
	}
	trans := make([]types.Transition, len(ts))
	for i := range ts {
		p, err := ts[i].params()
		if err != nil {
			return nil, err
		}
		trans[i] = types.Transition{Block: new(big.Int).Set(&ts[i].Block.Int), WBFT: &p}
	}
	return types.NewConfig(base, trans, init, chainID), nil
}

func (c *pureConfig) config() (*types.Config, error) {
	return buildConfig(&c.WBFT, c.Transitions, types.GenesisInit{}, nil)
}

// preset is the part of a network preset (B-01 §11) that the handlers of
// this adapter read: the chain id and the London block.
type preset struct {
	chainID *big.Int
	london  *big.Int
}

var presets = map[string]preset{
	"8282": {chainID: big.NewInt(8282), london: big.NewInt(0)},
	"8283": {chainID: big.NewInt(8283), london: big.NewInt(0)},
}

// chainConfig is the "config" of a chain fixture.
type chainConfig struct {
	Preset string `json:"preset"`
	Init   struct {
		Validators    []Hex `json:"validators"`
		BLSPublicKeys []Hex `json:"bls_public_keys"`
	} `json:"init"`
	WBFT         wbftSection    `json:"wbft"`
	Transitions  []transitionIn `json:"transitions"`
	ShanghaiTime *Dec           `json:"shanghai_time"`
	CancunTime   *Dec           `json:"cancun_time"`
	BohoBlock    *Dec           `json:"boho_block"`
}

// forks are the fork activations the Part B steps of header verification
// read.
type forks = snetpartb.Forks

func optU64(d *Dec) (*uint64, error) {
	if d == nil {
		return nil, nil
	}
	v, err := d.Uint64Checked()
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *chainConfig) build() (*types.Config, forks, error) {
	p, ok := presets[c.Preset]
	if !ok {
		return nil, forks{}, fmt.Errorf("%w: preset %q", errUnsupported, c.Preset)
	}
	var init types.GenesisInit
	for _, v := range c.Init.Validators {
		a, err := toAddress(v)
		if err != nil {
			return nil, forks{}, err
		}
		init.Validators = append(init.Validators, a)
	}
	init.BLSPublicKeys = hexBytes(c.Init.BLSPublicKeys)
	cfg, err := buildConfig(&c.WBFT, c.Transitions, init, p.chainID)
	if err != nil {
		return nil, forks{}, err
	}
	f := forks{London: p.london}
	if f.Shanghai, err = optU64(c.ShanghaiTime); err != nil {
		return nil, forks{}, err
	}
	if f.Cancun, err = optU64(c.CancunTime); err != nil {
		return nil, forks{}, err
	}
	return cfg, f, nil
}

// fixtureIn is the "chain" input.
type fixtureIn struct {
	Config       chainConfig `json:"config"`
	Genesis      Hex         `json:"genesis"`
	Headers      []Hex       `json:"headers"`
	NonCanonical []Hex       `json:"non_canonical"`
}

// fixtureChain is a types.ChainReader over a chain fixture. Canonical headers
// are indexed by the low 64 bits of their number; every header, canonical or
// not, is found by hash.
type fixtureChain struct {
	byHash map[types.Hash]*types.Header
	byNum  map[uint64]*types.Header
	head   *types.Header
}

func (f *fixtureIn) build() (*fixtureChain, *types.Config, forks, error) {
	cfg, fk, err := f.Config.build()
	if err != nil {
		return nil, nil, forks{}, err
	}
	c := &fixtureChain{byHash: map[types.Hash]*types.Header{}, byNum: map[uint64]*types.Header{}}
	for _, b := range append([]Hex{f.Genesis}, f.Headers...) {
		h, err := codec.DecodeHeader(b)
		if err != nil {
			return nil, nil, forks{}, err
		}
		c.byHash[codec.BlockHash(h)] = h
		c.byNum[h.Number.RefLow64()] = h //wbft:low64 HH-60 (canonical index of the fixture store)
		if c.head == nil || h.Number.Cmp(c.head.Number) > 0 {
			c.head = h
		}
	}
	for _, b := range f.NonCanonical {
		h, err := codec.DecodeHeader(b)
		if err != nil {
			return nil, nil, forks{}, err
		}
		c.byHash[codec.BlockHash(h)] = h
	}
	return c, cfg, fk, nil
}

func (c *fixtureChain) Head() *types.Header                        { return c.head }
func (c *fixtureChain) HeaderByNumber(idx uint64) *types.Header    { return c.byNum[idx] }
func (c *fixtureChain) HeaderByHash(hash types.Hash) *types.Header { return c.byHash[hash] }
func (c *fixtureChain) Header(hash types.Hash, idx uint64) *types.Header {
	h := c.byHash[hash]
	if h == nil || h.Number.RefLow64() != idx { //wbft:low64 HH-60
		return nil
	}
	return h
}
func (c *fixtureChain) HasBlock(hash types.Hash, idx uint64) bool { return c.Header(hash, idx) != nil }

func hConfigAt(_ string, input json.RawMessage) (any, error) {
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
	p := cfg.ConfigAt(n)
	var pol any
	if p.ProposerPolicy != nil {
		pol = decOut(p.ProposerPolicy.ID)
	}
	return obj{
		"request_timeout":             decOut(p.RequestTimeoutMs),
		"block_period":                decOut(p.BlockPeriodSeconds),
		"epoch":                       decOut(p.EpochLength),
		"proposer_policy":             pol,
		"max_request_timeout_seconds": decOut(p.MaxRequestTimeoutSeconds),
		"allowed_future_block_time":   decOut(p.AllowedFutureBlockTime),
	}, nil
}
