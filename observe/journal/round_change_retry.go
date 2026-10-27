package journal

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

const RoundChangeRetryProfile uint64 = 1

// RoundChangeRetryOptions declares the explicit local retry policy. It changes
// no wire message or chain rule. Nil keeps the complete old header encoding.
type RoundChangeRetryOptions struct {
	Profile       uint64 `json:"profile"`
	MaxIntervalMs uint64 `json:"max_interval_ms,string"`
}

func (o *RoundChangeRetryOptions) Validate() error {
	if o != nil && (o.Profile != RoundChangeRetryProfile || o.MaxIntervalMs == 0 || o.MaxIntervalMs > uint64(math.MaxInt64/int64(time.Millisecond))) {
		return fmt.Errorf("journal: unsupported round-change retry policy")
	}
	return nil
}

// RetryOptions returns fresh functional options only after profile, duration
// and all effective base timeouts are validated against the actual config.
func (o CoreOptions) RetryOptions(config *types.Config) (*consensus.RoundChangeRetryOptions, error) {
	if err := o.RoundChangeRetry.Validate(); err != nil {
		return nil, err
	}
	if o.RoundChangeRetry == nil {
		return nil, nil
	}
	options := &consensus.RoundChangeRetryOptions{MaxIntervalMs: o.RoundChangeRetry.MaxIntervalMs}
	return options, options.Validate(config)
}

// ValidateCoreDeclaration binds frozen diagnostic/header values to actual
// runtime options. It does not grant functional cache replay capability.
func (o CoreOptions) ValidateCoreDeclaration(actual consensus.Options) error {
	if o.Self != actual.Self || o.Improvements != uint64(actual.Improvements) || actual.BacklogLimit < 0 || o.BacklogLimit != uint64(actual.BacklogLimit) {
		return fmt.Errorf("journal: actual core options differ from declaration")
	}
	config, err := types.ParseChainConfig(o.ChainConfig)
	if err != nil {
		return err
	}
	switch o.ProposerPolicyProfile {
	case "":
	case CheckedProposerPolicyProfile:
		config, err = config.CheckedProposerPolicy()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("journal: unsupported proposer policy declaration")
	}
	retry, err := o.RetryOptions(config)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(config, actual.Config) || !reflect.DeepEqual(retry, actual.RoundChangeRetry) {
		return fmt.Errorf("journal: actual retry policy or chain configuration differs from declaration")
	}
	return nil
}

func (o *RoundChangeRetryOptions) encode() []uint64 {
	if o == nil {
		return nil
	}
	return []uint64{o.Profile, o.MaxIntervalMs}
}

func decodeRoundChangeRetryOptions(raw []uint64) (*RoundChangeRetryOptions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != 2 {
		return nil, fmt.Errorf("journal: round-change retry field count")
	}
	// Retain unknown declarations for diagnosis; Validate refuses capability.
	return &RoundChangeRetryOptions{Profile: raw[0], MaxIntervalMs: raw[1]}, nil
}

func validRetrySource(s transport.RoundChangeRetrySource) bool {
	if s == (transport.RoundChangeRetrySource{}) {
		return true
	}
	if s.Version != 1 || s.Generation == 0 || s.SigningKey == (types.Hash{}) {
		return false
	}
	if (s.EngineRun == 0 || s.Step == 0 || s.Output == 0) && (s.EngineRun != 0 || s.Step != 0 || s.Output != 0) {
		return false
	}
	for index, value := range []string{s.Height, s.Round} {
		n, ok := new(big.Int).SetString(value, 10)
		if !ok || n.Sign() < 0 || n.String() != value || index == 0 && n.Sign() == 0 {
			return false
		}
	}
	return true
}

func encodeRetrySource(s transport.RoundChangeRetrySource) ([]byte, error) {
	if !validRetrySource(s) {
		return nil, fmt.Errorf("journal: invalid round-change retry source")
	}
	if s == (transport.RoundChangeRetrySource{}) {
		return nil, nil
	}
	return rlp.Encode(s)
}

func decodeRetrySource(raw []byte) (transport.RoundChangeRetrySource, error) {
	var s transport.RoundChangeRetrySource
	if len(raw) == 0 {
		return s, nil
	}
	if err := rlp.DecodeStrict(raw, &s); err != nil || s.Version == 0 || !validRetrySource(s) {
		return s, fmt.Errorf("%w: round-change retry source", ErrRecord)
	}
	return s, nil
}

func retrySourceSize(s transport.RoundChangeRetrySource) int64 {
	if s == (transport.RoundChangeRetrySource{}) {
		return 0
	}
	return 128 + int64(len(s.Height)+len(s.Round))
}
