package journal

import (
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
)

const RecentObservationProfile uint64 = 1

// ObservationOptions binds the observation-only policy and a writer-start
// checkpoint. A checkpoint still needs an independently supplied chain anchor.
// Decimal strings preserve chain identity and heights without a 64-bit limit.
type ObservationOptions struct {
	Profile         uint64      `json:"profile"`
	ChainID         string      `json:"chain_id"`
	GenesisHash     types.Hash  `json:"genesis_hash"`
	Activation      string      `json:"activation"`
	Retention       string      `json:"retention"`
	Window          uint64      `json:"window,string"`
	Codec           wire.Limits `json:"codec"`
	StateBytes      uint64      `json:"state_bytes,string"`
	CheckpointBytes uint64      `json:"checkpoint_bytes,string"`
	AddressRows     uint32      `json:"address_rows"`
	HistoryWalk     uint64      `json:"history_walk,string"`
	ReplayHeaders   uint64      `json:"replay_headers,string"`
	PolicyDigest    types.Hash  `json:"policy_digest"`
	Checkpoint      []byte      `json:"checkpoint,omitempty"`
}

// NewObservationOptions records an explicit policy without supplying defaults.
func NewObservationOptions(policy window.Config, retention types.Height, walk, replay uint64) (*ObservationOptions, error) {
	engine, err := window.NewRecent(policy, retention)
	if err != nil || walk == 0 || replay == 0 {
		return nil, fmt.Errorf("journal: invalid observation policy or replay limits")
	}
	return &ObservationOptions{Profile: RecentObservationProfile, ChainID: policy.ChainID.String(), GenesisHash: policy.GenesisHash,
		Activation: policy.Activation.String(), Retention: retention.String(), Window: policy.Window, Codec: policy.Codec,
		StateBytes: policy.StateBytes, CheckpointBytes: policy.CheckpointBytes, AddressRows: policy.AddressRows,
		HistoryWalk: walk, ReplayHeaders: replay, PolicyDigest: engine.Digest()}, nil
}

func observationNumber(value string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 || n.String() != value {
		return nil, fmt.Errorf("journal: noncanonical observation integer")
	}
	return n, nil
}

// Engine validates the declared profile and exact policy commitment.
func (o *ObservationOptions) Engine() (*window.Engine, error) {
	if o == nil || o.Profile != RecentObservationProfile || o.HistoryWalk == 0 || o.ReplayHeaders == 0 || uint64(len(o.Checkpoint)) > o.CheckpointBytes {
		return nil, fmt.Errorf("journal: unsupported observation profile or replay limits")
	}
	id, err := observationNumber(o.ChainID)
	if err != nil {
		return nil, err
	}
	a, err := observationNumber(o.Activation)
	if err != nil {
		return nil, err
	}
	h, err := observationNumber(o.Retention)
	if err != nil {
		return nil, err
	}
	engine, err := window.NewRecent(window.Config{ChainID: id, GenesisHash: o.GenesisHash, Activation: types.MustHeightFromBig(a),
		Window: o.Window, Codec: o.Codec, StateBytes: o.StateBytes, CheckpointBytes: o.CheckpointBytes, AddressRows: o.AddressRows}, types.MustHeightFromBig(h))
	if err != nil {
		return nil, err
	}
	if engine.Digest() != o.PolicyDigest {
		return nil, fmt.Errorf("journal: observation policy digest differs")
	}
	return engine, nil
}

func (o *ObservationOptions) Validate() error {
	if o == nil {
		return nil
	}
	_, err := o.Engine()
	return err
}

func (o *ObservationOptions) ValidateIdentity(chainID *big.Int, genesis types.Hash) error {
	if o == nil {
		return nil
	}
	if err := o.Validate(); err != nil {
		return err
	}
	if chainID == nil || chainID.String() != o.ChainID || genesis != o.GenesisHash {
		return fmt.Errorf("journal: observation chain identity differs")
	}
	return nil
}

func (o *ObservationOptions) encode() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return rlp.Encode(o)
}

func decodeObservationOptions(raw []byte) (*ObservationOptions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var options ObservationOptions
	if err := rlp.DecodeStrict(raw, &options); err != nil {
		return nil, err
	}
	if len(options.Checkpoint) == 0 {
		options.Checkpoint = nil
	}
	// Unknown profiles remain readable for diagnosis; Engine refuses them.
	return &options, nil
}
