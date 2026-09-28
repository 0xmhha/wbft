package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// headerSource fetches one header by number or hash with the hash the node
// reported for it.
type headerSource interface {
	headerByNumber(ctx context.Context, n uint64) (*types.Header, types.Hash, error)
	headerByHash(ctx context.Context, hash types.Hash) (*types.Header, types.Hash, error)
}

// rpcChain is a types.ChainReader over a node's canonical chain. Headers are
// fetched on demand and kept. The reader interface has no error result, so
// the first fetch error is kept in err and the lookup returns nil.
type rpcChain struct {
	ctx    context.Context
	src    headerSource
	byNum  map[uint64]*types.Header
	byHash map[types.Hash]*types.Header
	head   *types.Header
	err    error
}

func newRPCChain(ctx context.Context, src headerSource) *rpcChain {
	return &rpcChain{ctx: ctx, src: src, byNum: map[uint64]*types.Header{}, byHash: map[types.Hash]*types.Header{}}
}

func (c *rpcChain) add(h *types.Header) {
	c.byNum[h.Number.RefLow64()] = h // the scanned heights are far below 2^64
	c.byHash[codec.BlockHash(h)] = h
	if c.head == nil || h.Number.Cmp(c.head.Number) > 0 {
		c.head = h
	}
}

// fetch returns the canonical header at n. It fails when the hash wbft
// computes differs from the hash the node reports, since every later check
// would then compare the wrong values.
func (c *rpcChain) fetch(n uint64) (*types.Header, error) {
	if h, ok := c.byNum[n]; ok {
		return h, nil
	}
	h, reported, err := c.src.headerByNumber(c.ctx, n)
	if err != nil {
		return nil, err
	}
	if got := codec.BlockHash(h); got != reported {
		return nil, &hashMismatchError{number: n, reported: reported, computed: got}
	}
	c.add(h)
	return h, nil
}

type hashMismatchError struct {
	number             uint64
	reported, computed types.Hash
}

func (e *hashMismatchError) Error() string {
	return fmt.Sprintf("block %d: node reports hash %s, wbft computes %s", e.number, e.reported.Hex(), e.computed.Hex())
}

func (c *rpcChain) note(err error) {
	if c.err == nil {
		c.err = err
	}
}

func (c *rpcChain) Head() *types.Header { return c.head }

func (c *rpcChain) HeaderByNumber(idx uint64) *types.Header {
	h, err := c.fetch(idx)
	if err != nil {
		if !errors.Is(err, errNotFound) {
			c.note(err)
		}
		return nil
	}
	return h
}

func (c *rpcChain) Header(hash types.Hash, idx uint64) *types.Header {
	if h := c.HeaderByNumber(idx); h != nil && codec.BlockHash(h) == hash {
		return h
	}
	return nil
}

func (c *rpcChain) HeaderByHash(hash types.Hash) *types.Header {
	if h, ok := c.byHash[hash]; ok {
		return h
	}
	h, reported, err := c.src.headerByHash(c.ctx, hash)
	if err != nil {
		if !errors.Is(err, errNotFound) {
			c.note(err)
		}
		return nil
	}
	if codec.BlockHash(h) != reported || reported != hash {
		c.note(&hashMismatchError{number: h.Number.RefLow64(), reported: reported, computed: codec.BlockHash(h)})
		return nil
	}
	c.add(h)
	return h
}

func (c *rpcChain) HasBlock(hash types.Hash, idx uint64) bool { return c.Header(hash, idx) != nil }

// trusted gives VerifyLight the validator sets from the fetched epoch
// headers.
type trusted struct {
	chain types.ChainReader
	cfg   *types.Config
}

func (t *trusted) ValidatorsAt(n types.Height, parentHash types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(t.chain, t.cfg, n, parentHash, nil)
}

// blockRange is an inclusive range of block numbers.
type blockRange struct{ from, to uint64 }

// scanRanges returns the ranges 0 .. span and f .. f+span for every fork
// block f > 0, merged where they overlap or touch and clipped to head.
func scanRanges(forks []uint64, span, head uint64) []blockRange {
	starts := []uint64{0}
	for _, f := range forks {
		if f > 0 {
			starts = append(starts, f)
		}
	}
	slices.Sort(starts)
	var out []blockRange
	for _, s := range starts {
		if s > head {
			continue
		}
		e := s + span
		if e < s || e > head { // overflow or past the head
			e = head
		}
		if n := len(out); n > 0 && s <= out[n-1].to+1 {
			out[n-1].to = max(out[n-1].to, e)
			continue
		}
		out = append(out, blockRange{s, e})
	}
	return out
}

// rejection is one header that a check did not accept.
type rejection struct {
	number uint64
	hash   types.Hash
	check  string // "VerifyHeader" or "VerifyLight"
	step   string // failing step, when known
	err    error
}

func (r rejection) String() string {
	step := r.step
	if step == "" {
		step = "-"
	}
	return fmt.Sprintf("REJECT block=%d hash=%s check=%s step=%s err=%v", r.number, r.hash.Hex(), r.check, step, r.err)
}

// result counts what a scan checked.
type result struct {
	ranges     []blockRange
	checked    int
	rejections []rejection
	requests   int
}

func (r *result) rejected() bool { return len(r.rejections) > 0 }

func (r *result) summary() string {
	rs := ""
	for i, br := range r.ranges {
		if i > 0 {
			rs += ","
		}
		rs += fmt.Sprintf("%d-%d", br.from, br.to)
	}
	return fmt.Sprintf("ranges=%s headers_checked=%d rejections=%d requests=%d", rs, r.checked, len(r.rejections), r.requests)
}

type scanner struct {
	cfg     *types.Config
	partB   header.PartB
	chain   *rpcChain
	out     io.Writer
	verbose bool
	now     func() time.Time
}

func stepOf(err error) string {
	var se *header.StepError
	if errors.As(err, &se) {
		return se.Step
	}
	return ""
}

// verify runs both checks on the canonical header at n (n >= 1) and returns
// its rejections.
func (s *scanner) verify(n uint64) ([]rejection, error) {
	h, err := s.chain.fetch(n)
	if err != nil {
		return nil, err
	}
	parent, err := s.chain.fetch(n - 1)
	if err != nil {
		return nil, err
	}
	hash := codec.BlockHash(h)
	var out []rejection
	env := &header.Env{Config: s.cfg, Chain: s.chain, PartB: s.partB, Now: s.now}
	verr := header.VerifyHeader(env, h, nil, header.Options{CheckSeals: true, Mode: header.HeaderOnly})
	if s.chain.err != nil {
		return nil, s.chain.err
	}
	if verr != nil {
		out = append(out, rejection{number: n, hash: hash, check: "VerifyHeader", step: stepOf(verr), err: verr})
	}
	res, lerr := header.VerifyLight(header.LightInputs{
		Config:  s.cfg,
		Trusted: &trusted{chain: s.chain, cfg: s.cfg},
		PartB:   s.partB,
		Now:     s.now,
	}, h, parent)
	if s.chain.err != nil {
		return nil, s.chain.err
	}
	if res != header.Valid {
		out = append(out, rejection{number: n, hash: hash, check: "VerifyLight " + res.String(), step: stepOf(lerr), err: lerr})
	}
	return out, nil
}

// scan checks the chain ID and the genesis hash, then verifies every header
// of the scan ranges in order.
func (s *scanner) scan(ctx context.Context, c *client, forks []uint64, span uint64, genesisHash string) (*result, error) {
	res := &result{}
	defer func() { res.requests = c.requests }()
	id, err := c.chainID(ctx)
	if err != nil {
		return res, fmt.Errorf("eth_chainId: %w", err)
	}
	if id.Cmp(s.cfg.ChainID) != 0 {
		return res, fmt.Errorf("node chain ID %s, configuration chain ID %s", id, s.cfg.ChainID)
	}
	head, err := c.blockNumber(ctx)
	if err != nil {
		return res, fmt.Errorf("eth_blockNumber: %w", err)
	}
	res.ranges = scanRanges(forks, span, head)
	fmt.Fprintf(s.out, "headerscan: chain %s head %d\n", id, head)
	genesis, err := s.chain.fetch(0)
	if err != nil {
		return res, err
	}
	if genesisHash != "" && codec.BlockHash(genesis).Hex() != genesisHash {
		return res, fmt.Errorf("genesis hash %s, want %s", codec.BlockHash(genesis).Hex(), genesisHash)
	}
	for _, br := range res.ranges {
		fmt.Fprintf(s.out, "headerscan: range %d-%d\n", br.from, br.to)
		for n := max(br.from, 1); n <= br.to; n++ {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			rej, err := s.verify(n)
			if err != nil {
				return res, err
			}
			res.checked++
			for _, r := range rej {
				fmt.Fprintln(s.out, r)
			}
			res.rejections = append(res.rejections, rej...)
			if s.verbose && len(rej) == 0 {
				fmt.Fprintf(s.out, "ok block=%d\n", n)
			}
		}
	}
	return res, nil
}
