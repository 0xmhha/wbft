package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/0xmhha/wbft/internal/refsort"
)

// ProposerPolicy identifies the proposer rotation rule. Identifier 1 selects
// Sticky; every other identifier selects RoundRobin, but the identifier
// itself is kept (config_at reports it).
//
// Spec: WBFT-PARAM-020
type ProposerPolicy struct {
	ID uint64
}

// Proposer policy identifiers.
const (
	RoundRobin uint64 = 0
	Sticky     uint64 = 1
)

// IsSticky reports whether the policy is Sticky.
//
// Spec: WBFT-PROP-005
func (p ProposerPolicy) IsSticky() bool { return p.ID == Sticky }

// WBFTParams is the anzeon.wbft section of the chain configuration, or the
// WBFT fields of a transition. For RequestTimeoutSeconds, BlockPeriodSeconds,
// EpochLength and AllowedFutureBlockTime, 0 and absent mean the same; the two
// pointer fields are nil when absent.
type WBFTParams struct {
	RequestTimeoutSeconds    uint64  `json:"requestTimeoutSeconds"`
	BlockPeriodSeconds       uint64  `json:"blockPeriodSeconds"`
	EpochLength              uint64  `json:"epochLength"`
	AllowedFutureBlockTime   uint64  `json:"allowedFutureBlockTime,omitempty"`
	ProposerPolicy           *uint64 `json:"proposerPolicy"`
	MaxRequestTimeoutSeconds *uint64 `json:"maxRequestTimeoutSeconds"`
}

// Transition changes WBFT parameters from Block onwards. Block is nil when
// the configuration gives no block; WBFT is nil when the entry carries no
// WBFT field.
type Transition struct {
	Block *big.Int
	WBFT  *WBFTParams
}

// GenesisInit is anzeon.init: the genesis validators and their BLS public
// keys, in configuration order.
type GenesisInit struct {
	Validators    []Address
	BLSPublicKeys [][]byte
}

// Params is the configuration that governs one height: config_at(number).
type Params struct {
	RequestTimeoutMs         uint64          // round-change base timeout (ms)
	BlockPeriodSeconds       uint64          // minimum distance of header times
	EpochLength              uint64          // blocks per epoch (length only; see validator.EpochSchedule)
	ProposerPolicy           *ProposerPolicy // nil when never configured
	MaxRequestTimeoutSeconds uint64          // cap of the round timeout for rounds >= 1; 0 is no cap
	AllowedFutureBlockTime   uint64          // from the base configuration only
}

// Config is the consensus configuration of a chain: the base parameters
// built from anzeon.wbft, the transitions sorted by block, the genesis
// validators and the chain id. It is immutable after construction.
type Config struct {
	base        Params
	transitions []Transition
	Init        GenesisInit
	ChainID     *big.Int
}

// NewConfig builds the configuration a node derives from anzeon.wbft and the
// transitions of the chain configuration: it starts from the all-zero
// configuration, applies the non-zero or present fields of wbft, and sorts
// the transitions (SortTransitions). The inputs are copied.
//
// Spec: WBFT-PARAM-030
func NewConfig(wbft WBFTParams, transitions []Transition, init GenesisInit, chainID *big.Int) *Config {
	c := &Config{Init: copyInit(init)}
	if chainID != nil {
		c.ChainID = new(big.Int).Set(chainID)
	}
	if wbft.RequestTimeoutSeconds != 0 {
		// uint64 product, wrapping modulo 2^64 as in the reference.
		c.base.RequestTimeoutMs = wbft.RequestTimeoutSeconds * 1000
	}
	if wbft.BlockPeriodSeconds != 0 {
		c.base.BlockPeriodSeconds = wbft.BlockPeriodSeconds
	}
	if wbft.EpochLength != 0 {
		c.base.EpochLength = wbft.EpochLength
	}
	if wbft.AllowedFutureBlockTime != 0 {
		c.base.AllowedFutureBlockTime = wbft.AllowedFutureBlockTime
	}
	if wbft.ProposerPolicy != nil {
		c.base.ProposerPolicy = &ProposerPolicy{ID: *wbft.ProposerPolicy}
	}
	if wbft.MaxRequestTimeoutSeconds != nil {
		c.base.MaxRequestTimeoutSeconds = *wbft.MaxRequestTimeoutSeconds
	}
	ts := make([]Transition, len(transitions))
	for i, t := range transitions {
		ts[i] = copyTransition(t)
	}
	c.transitions = SortTransitions(ts)
	return c
}

func copyInit(in GenesisInit) GenesisInit {
	out := GenesisInit{Validators: append([]Address(nil), in.Validators...)}
	for _, k := range in.BLSPublicKeys {
		out.BLSPublicKeys = append(out.BLSPublicKeys, append([]byte(nil), k...))
	}
	return out
}

func copyTransition(t Transition) Transition {
	var c Transition
	if t.Block != nil {
		c.Block = new(big.Int).Set(t.Block)
	}
	if t.WBFT != nil {
		w := *t.WBFT
		if w.ProposerPolicy != nil {
			p := *w.ProposerPolicy
			w.ProposerPolicy = &p
		}
		if w.MaxRequestTimeoutSeconds != nil {
			m := *w.MaxRequestTimeoutSeconds
			w.MaxRequestTimeoutSeconds = &m
		}
		c.WBFT = &w
	}
	return c
}

// SortTransitions sorts ts in place by ascending block and returns it. Entries
// without a block go last. Entries with an equal block are ordered as the
// reference implementation orders them (internal/refsort).
func SortTransitions(ts []Transition) []Transition {
	refsort.Slice(ts, func(i, j int) bool {
		if ts[i].Block == nil {
			return false
		}
		if ts[j].Block == nil {
			return true
		}
		return ts[i].Block.Cmp(ts[j].Block) < 0
	})
	return ts
}

// Transitions returns a copy of the sorted transitions.
func (c *Config) Transitions() []Transition {
	out := make([]Transition, len(c.transitions))
	for i, t := range c.transitions {
		out[i] = copyTransition(t)
	}
	return out
}

// Base returns the base parameters (the configuration before transitions).
func (c *Config) Base() Params { return c.base.copy() }

func (p Params) copy() Params {
	if p.ProposerPolicy != nil {
		pp := *p.ProposerPolicy
		p.ProposerPolicy = &pp
	}
	return p
}

// ConfigAt is config_at(number): the base parameters with every transition
// whose block is at most number applied in sorted order. A zero
// requestTimeoutSeconds, blockPeriodSeconds or epochLength does not override;
// a present proposerPolicy or maxRequestTimeoutSeconds overrides even when 0;
// allowedFutureBlockTime is never taken from a transition.
//
// A transition without a block number sorts after all others and is never
// applied; one without WBFT fields applies nothing. The node refuses such
// configurations before use (CheckTransitions).
//
// Spec: WBFT-PARAM-050, WBFT-PARAM-051, WBFT-PARAM-052, WBFT-PARAM-033
func (c *Config) ConfigAt(number Height) Params {
	p := c.base.copy()
	n := number.big()
	for _, t := range c.transitions {
		if t.Block == nil || t.Block.Cmp(n) > 0 {
			break
		}
		w := t.WBFT
		if w == nil {
			continue
		}
		if w.RequestTimeoutSeconds != 0 {
			p.RequestTimeoutMs = w.RequestTimeoutSeconds * 1000
		}
		if w.BlockPeriodSeconds != 0 {
			p.BlockPeriodSeconds = w.BlockPeriodSeconds
		}
		if w.EpochLength != 0 {
			p.EpochLength = w.EpochLength
		}
		if w.ProposerPolicy != nil {
			p.ProposerPolicy = &ProposerPolicy{ID: *w.ProposerPolicy}
		}
		if w.MaxRequestTimeoutSeconds != nil {
			p.MaxRequestTimeoutSeconds = *w.MaxRequestTimeoutSeconds
		}
	}
	return p
}

// EpochTransition is one re-anchoring of the epoch schedule: a transition
// with a non-zero epoch length.
type EpochTransition struct {
	Block  *big.Int
	Length uint64
}

// EpochTransitions returns, in sorted order, the transitions reached by a
// walk up to the first entry without a block, keeping those that set a
// non-zero epoch length. The epoch schedule of package validator is built
// from them.
func (c *Config) EpochTransitions() []EpochTransition {
	var out []EpochTransition
	for _, t := range c.transitions {
		if t.Block == nil {
			break
		}
		if t.WBFT == nil || t.WBFT.EpochLength == 0 {
			continue
		}
		out = append(out, EpochTransition{Block: new(big.Int).Set(t.Block), Length: t.WBFT.EpochLength})
	}
	return out
}

// ErrConfig is a chain configuration error.
type ErrConfig struct {
	Field  string
	Reason string
}

func (e *ErrConfig) Error() string { return fmt.Sprintf("chain config: %s: %s", e.Field, e.Reason) }

// CheckTransitions reports a transition that has no block number or no WBFT
// field. Such an entry makes the configuration unusable once it is reached,
// so a node refuses it at start-up.
func (c *Config) CheckTransitions() error {
	for i, t := range c.transitions {
		if t.Block == nil {
			return &ErrConfig{Field: fmt.Sprintf("transitions[%d].block", i), Reason: "missing"}
		}
		if t.WBFT == nil {
			return &ErrConfig{Field: fmt.Sprintf("transitions[%d]", i), Reason: "no WBFT field"}
		}
	}
	return nil
}

// chainConfigJSON is the part of the genesis chain configuration that wbft
// reads.
type chainConfigJSON struct {
	ChainID     *big.Int         `json:"chainId"`
	Anzeon      *anzeonJSON      `json:"anzeon"`
	Transitions []transitionJSON `json:"transitions"`
}

type anzeonJSON struct {
	WBFT *WBFTParams `json:"wbft"`
	Init *struct {
		Validators    []Address `json:"validators"`
		BLSPublicKeys []string  `json:"blsPublicKeys"`
	} `json:"init"`
}

// transitionJSON mirrors the reference Transition: a block and the embedded
// WBFT fields, which stay nil when the entry carries none of them.
type transitionJSON struct {
	Block *big.Int `json:"block"`
	*WBFTParams
}

// ParseChainConfig parses the consensus part of a genesis chain
// configuration (the "config" object of a genesis file): chainId,
// anzeon.wbft, anzeon.init and transitions. It only parses; whether a node
// starts with the result is decided by the node's start-up checks.
func ParseChainConfig(raw []byte) (*Config, error) {
	var cc chainConfigJSON
	if err := json.Unmarshal(raw, &cc); err != nil {
		return nil, &ErrConfig{Field: "config", Reason: err.Error()}
	}
	if cc.Anzeon == nil || cc.Anzeon.WBFT == nil {
		return nil, &ErrConfig{Field: "anzeon.wbft", Reason: "missing"}
	}
	var init GenesisInit
	if cc.Anzeon.Init != nil {
		init.Validators = cc.Anzeon.Init.Validators
		for i, s := range cc.Anzeon.Init.BLSPublicKeys {
			k, err := decodeHex0x(s)
			if err != nil {
				return nil, &ErrConfig{Field: fmt.Sprintf("anzeon.init.blsPublicKeys[%d]", i), Reason: err.Error()}
			}
			init.BLSPublicKeys = append(init.BLSPublicKeys, k)
		}
	}
	ts := make([]Transition, len(cc.Transitions))
	for i, t := range cc.Transitions {
		ts[i] = Transition{Block: t.Block, WBFT: t.WBFTParams}
	}
	return NewConfig(*cc.Anzeon.WBFT, ts, init, cc.ChainID), nil
}

// decodeHex0x decodes a 0x-prefixed hex string, as hexutil.Decode does.
func decodeHex0x(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, fmt.Errorf("hex string without 0x prefix")
	}
	return hex.DecodeString(s[2:])
}
