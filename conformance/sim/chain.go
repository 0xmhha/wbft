package sim

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// ChainID is the chain id of simulated chains.
const ChainID = 8282

// chainConfigJSON writes the chain configuration of a scenario as the
// "config" object of a genesis file.
func chainConfigJSON(p Params, genesis []Validator) ([]byte, error) {
	pol := uint64(0)
	type wbftJSON struct {
		RequestTimeoutSeconds    uint64  `json:"requestTimeoutSeconds"`
		BlockPeriodSeconds       uint64  `json:"blockPeriodSeconds"`
		EpochLength              uint64  `json:"epochLength"`
		ProposerPolicy           *uint64 `json:"proposerPolicy"`
		MaxRequestTimeoutSeconds *uint64 `json:"maxRequestTimeoutSeconds,omitempty"`
	}
	init := struct {
		Validators    []string `json:"validators"`
		BLSPublicKeys []string `json:"blsPublicKeys"`
	}{}
	for _, v := range genesis {
		init.Validators = append(init.Validators, "0x"+hex.EncodeToString(v.address[:]))
		init.BLSPublicKeys = append(init.BLSPublicKeys, "0x"+hex.EncodeToString(v.blsPub))
	}
	cfg := map[string]any{
		"chainId": ChainID,
		"anzeon": map[string]any{
			"wbft": wbftJSON{RequestTimeoutSeconds: p.RequestTimeoutSeconds, BlockPeriodSeconds: p.BlockPeriodSeconds,
				EpochLength: p.EpochLength, ProposerPolicy: &pol, MaxRequestTimeoutSeconds: p.MaxRequestTimeoutSeconds},
			"init": init,
		},
	}
	return json.Marshal(cfg)
}

// genesisBlock returns block 0 with the genesis EpochInfo.
func genesisBlock(cfg *types.Config) (*types.Block, error) {
	ei, err := epoch.InitialEpochInfo(cfg.Init)
	if err != nil {
		return nil, err
	}
	g := &types.Header{
		UncleHash:  types.EmptyUncleHash,
		Root:       keccak.Sum256([]byte("wbft-sim-genesis")),
		Difficulty: big.NewInt(1),
		Number:     types.HeightFromUint64(0),
		GasLimit:   30_000_000,
		Time:       uint64(Epoch.Unix()) - 1,
		BaseFee:    big.NewInt(20_000_000_000_000),
	}
	if err := codec.SetExtra(g, &types.WBFTExtra{GasTip: new(big.Int).SetUint64(types.InitialGasTip), EpochInfo: ei}); err != nil {
		return nil, err
	}
	return &types.Block{Header: g, Body: types.BodyRaw{{0xc0}, {0xc0}}}, nil
}

// memChain is a chain store: canonical headers by index and every stored
// header by hash. It implements types.ChainReader.
type memChain struct {
	byNum  map[uint64]*types.Block
	byHash map[types.Hash]*types.Block
	head   *types.Block
}

func newMemChain(g *types.Block) *memChain {
	c := &memChain{byNum: map[uint64]*types.Block{}, byHash: map[types.Hash]*types.Block{}}
	c.insert(g)
	return c
}

// index is the canonical index of a header; simulated chains stay below
// 2^64.
func index(h *types.Header) uint64 {
	if !h.Number.IsUint64() {
		return ^uint64(0)
	}
	return h.Number.Big().Uint64()
}

func (c *memChain) insert(b *types.Block) {
	c.byNum[index(b.Header)] = b
	c.byHash[codec.BlockHash(b.Header)] = b
	c.head = b
}

func (c *memChain) Head() *types.Header { return c.head.Header }
func (c *memChain) HeaderByNumber(idx uint64) *types.Header {
	if b := c.byNum[idx]; b != nil {
		return b.Header
	}
	return nil
}
func (c *memChain) Header(hash types.Hash, idx uint64) *types.Header {
	if b := c.byHash[hash]; b != nil && index(b.Header) == idx {
		return b.Header
	}
	return nil
}
func (c *memChain) HeaderByHash(hash types.Hash) *types.Header {
	if b := c.byHash[hash]; b != nil {
		return b.Header
	}
	return nil
}
func (c *memChain) HasBlock(hash types.Hash, idx uint64) bool { return c.Header(hash, idx) != nil }

// ChainSource answers stepdriver.BlockSource and types.ChainReader from a
// list of canonical blocks.
type ChainSource struct{ c *memChain }

// NewChainSource returns a source over blocks 0 .. n in order.
func NewChainSource(blocks []*types.Block) (*ChainSource, error) {
	if len(blocks) == 0 {
		return nil, fmt.Errorf("sim: empty chain")
	}
	c := newMemChain(blocks[0])
	for _, b := range blocks[1:] {
		c.insert(b)
	}
	return &ChainSource{c: c}, nil
}

// Reader returns the source as a chain reader.
func (s *ChainSource) Reader() types.ChainReader { return s.c }

// HeaderByNumber returns the canonical header at n.
func (s *ChainSource) HeaderByNumber(n types.Height) (*types.Header, error) {
	h := s.c.HeaderByNumber(index(&types.Header{Number: n}))
	if h == nil {
		return nil, fmt.Errorf("sim: no header %s", n)
	}
	return h, nil
}

// BlockByHash returns the block with hash h.
func (s *ChainSource) BlockByHash(h types.Hash) (*types.Block, error) {
	b := s.c.byHash[h]
	if b == nil {
		return nil, fmt.Errorf("sim: no block %x", h)
	}
	return b, nil
}

// EncodeChain encodes blocks as the chain file of a journal export: an RLP
// list of encoded blocks.
func EncodeChain(blocks []*types.Block) ([]byte, error) {
	items := make([][]byte, len(blocks))
	for i, b := range blocks {
		e, err := codec.EncodeBlock(b)
		if err != nil {
			return nil, err
		}
		items[i] = e
	}
	return rlpEncode(items)
}

// DecodeChain is the inverse of EncodeChain.
func DecodeChain(b []byte) ([]*types.Block, error) {
	var items [][]byte
	if err := rlpDecode(b, &items); err != nil {
		return nil, err
	}
	out := make([]*types.Block, len(items))
	for i, it := range items {
		blk, err := codec.DecodeBlock(it)
		if err != nil {
			return nil, err
		}
		out[i] = blk
	}
	return out, nil
}

func rlpEncode(v any) ([]byte, error) { return rlp.Encode(v) }

func rlpDecode(b []byte, v any) error { return rlp.DecodeStrict(b, v) }
