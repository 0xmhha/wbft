package kvstore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// Genesis is the genesis file of a kvstore chain: the chain configuration
// the consensus layer reads and block 0.
type Genesis struct {
	Config json.RawMessage `json:"config"`
	Block  string          `json:"block"` // 0x-prefixed RLP of block 0
}

// GenesisParams are the consensus parameters of a new chain.
type GenesisParams struct {
	ChainID               uint64
	BlockPeriodSeconds    uint64
	RequestTimeoutSeconds uint64
	EpochLength           uint64
	Time                  uint64 // header time of block 0
}

// Validator is a genesis validator.
type Validator struct {
	Address      types.Address
	BLSPublicKey []byte
}

// NewGenesis returns the genesis of a chain with the validators.
func NewGenesis(p GenesisParams, vals []Validator) (*Genesis, error) {
	var addrs, keys []string
	for _, v := range vals {
		addrs = append(addrs, "0x"+hex.EncodeToString(v.Address[:]))
		keys = append(keys, "0x"+hex.EncodeToString(v.BLSPublicKey))
	}
	pol := uint64(0) // round robin
	cfgJSON, err := json.Marshal(map[string]any{"chainId": p.ChainID, "anzeon": map[string]any{
		"wbft": map[string]any{"requestTimeoutSeconds": p.RequestTimeoutSeconds, "blockPeriodSeconds": p.BlockPeriodSeconds,
			"epochLength": p.EpochLength, "proposerPolicy": &pol},
		"init": map[string]any{"validators": addrs, "blsPublicKeys": keys}}})
	if err != nil {
		return nil, err
	}
	cfg, err := types.ParseChainConfig(cfgJSON)
	if err != nil {
		return nil, err
	}
	ei, err := epoch.InitialEpochInfo(cfg.Init)
	if err != nil {
		return nil, err
	}
	h := &types.Header{UncleHash: types.EmptyUncleHash, Root: emptyState().Root(), Difficulty: big.NewInt(1),
		Number: types.HeightFromUint64(0), GasLimit: 30_000_000, Time: p.Time, BaseFee: big.NewInt(1)}
	if err := codec.SetExtra(h, &types.WBFTExtra{GasTip: new(big.Int).SetUint64(types.InitialGasTip), EpochInfo: ei}); err != nil {
		return nil, err
	}
	raw, err := codec.EncodeBlock(&types.Block{Header: h, Body: types.BodyRaw{{0xc0}, {0xc0}}})
	if err != nil {
		return nil, err
	}
	return &Genesis{Config: cfgJSON, Block: "0x" + hex.EncodeToString(raw)}, nil
}

// ReadGenesis reads a genesis file.
func ReadGenesis(path string) (*Genesis, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g Genesis
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("kvstore: %s: %w", path, err)
	}
	return &g, nil
}

// Write writes the genesis file.
func (g *Genesis) Write(path string) error {
	raw, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// block decodes block 0.
func (g *Genesis) block() (*types.Block, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(g.Block, "0x"))
	if err != nil {
		return nil, err
	}
	return codec.DecodeBlock(raw)
}
