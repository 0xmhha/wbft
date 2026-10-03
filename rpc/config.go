package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/0xmhha/wbft/observe/evidence"
	"github.com/0xmhha/wbft/types"
)

// HeightArg is a block height given to an RPC method: a JSON number, or a
// string in decimal or 0x-hex. It is read as the full value (D-47), not its
// low 64 bits.
type HeightArg struct{ v *big.Int }

// UnmarshalJSON implements json.Unmarshaler.
func (h *HeightArg) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, `"`) {
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
	}
	v, ok := new(big.Int), false
	if rest, hex := strings.CutPrefix(strings.ToLower(s), "0x"); hex {
		v, ok = v.SetString(rest, 16)
	} else {
		v, ok = v.SetString(s, 10)
	}
	if !ok || v.Sign() < 0 {
		return fmt.Errorf("rpc: bad height %s", b)
	}
	h.v = v
	return nil
}

// ConfigAtResult is wbft_configAt: config_at(h) and the transitions that
// make it.
type ConfigAtResult struct {
	Number                   string             `json:"number"` // decimal
	RequestTimeoutMs         uint64             `json:"requestTimeoutMs"`
	BlockPeriodSeconds       uint64             `json:"blockPeriodSeconds"`
	EpochLength              uint64             `json:"epochLength"`
	ProposerPolicy           *uint64            `json:"proposerPolicy"` // null when never configured
	MaxRequestTimeoutSeconds uint64             `json:"maxRequestTimeoutSeconds"`
	AllowedFutureBlockTime   uint64             `json:"allowedFutureBlockTime"`
	Transitions              []TransitionResult `json:"transitions"` // applied at h, in order
}

// TransitionResult is a transition of the chain configuration.
type TransitionResult struct {
	Block string            `json:"block"` // decimal
	WBFT  *types.WBFTParams `json:"wbft"`
}

// ErrNoConfig reports a node without a chain configuration yet (not
// started).
var ErrNoConfig = errors.New("rpc: no chain configuration")

// ConfigAt is wbft_configAt(h).
func (s *Service) ConfigAt(h HeightArg) (*ConfigAtResult, error) {
	if h.v == nil {
		return nil, errors.New("rpc: a height is required")
	}
	cfg := s.b.ChainConfig()
	if cfg == nil {
		return nil, ErrNoConfig
	}
	n, err := types.HeightFromBig(h.v)
	if err != nil {
		return nil, err
	}
	p := cfg.ConfigAt(n)
	r := &ConfigAtResult{Number: h.v.String(), RequestTimeoutMs: p.RequestTimeoutMs, BlockPeriodSeconds: p.BlockPeriodSeconds,
		EpochLength: p.EpochLength, MaxRequestTimeoutSeconds: p.MaxRequestTimeoutSeconds,
		AllowedFutureBlockTime: p.AllowedFutureBlockTime, Transitions: []TransitionResult{}}
	if p.ProposerPolicy != nil {
		id := p.ProposerPolicy.ID
		r.ProposerPolicy = &id
	}
	for _, t := range cfg.Transitions() { // sorted; ConfigAt stops at the first not applied
		if t.Block == nil || t.Block.Cmp(h.v) > 0 {
			break
		}
		r.Transitions = append(r.Transitions, TransitionResult{Block: t.Block.String(), WBFT: t.WBFT})
	}
	return r, nil
}

// MaxRange bounds the heights of one range call (observe.md 6).
const MaxRange = 1024

// Evidence is wbft_evidence(from, to): the double-signing evidence the
// node detected at the heights from..to, at most MaxRange heights.
func (s *Service) Evidence(from, to HeightArg) ([]evidence.Record, error) {
	if from.v == nil || to.v == nil {
		return nil, errors.New("rpc: from and to are required")
	}
	span := new(big.Int).Sub(to.v, from.v)
	if span.Sign() < 0 || span.Cmp(big.NewInt(MaxRange)) >= 0 {
		return nil, fmt.Errorf("rpc: bad height range %s..%s (at most %d heights)", from.v, to.v, MaxRange)
	}
	return s.b.Evidence(from.v, to.v)
}
