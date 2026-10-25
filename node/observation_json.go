package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/types"
)

type observationCodecJSON struct {
	ExtraBytes     uint64 `json:"extraBytes"`
	Proofs         uint32 `json:"proofs"`
	SettlementRows uint32 `json:"settlementRows"`
	Validators     uint32 `json:"validators"`
}
type observationJSON struct {
	ChainID              string               `json:"chainId"`
	GenesisHash          types.Hash           `json:"genesisHash"`
	Activation           string               `json:"activation"`
	Retention            string               `json:"retention"`
	Window               uint64               `json:"window"`
	Codec                observationCodecJSON `json:"codec"`
	StateBytes           uint64               `json:"stateBytes"`
	CheckpointBytes      uint64               `json:"checkpointBytes"`
	AddressRows          uint32               `json:"addressRows"`
	HistoryWalk          uint64               `json:"historyWalk"`
	ReplayHeaders        uint64               `json:"replayHeaders"`
	WitnessItems         uint32               `json:"witnessItems"`
	WitnessBytes         uint64               `json:"witnessBytes"`
	WitnessChecksPerStep uint32               `json:"witnessChecksPerStep"`
}

func observationNatural(name, value string) (*big.Int, error) {
	number, ok := new(big.Int).SetString(value, 10)
	if !ok || number.Sign() < 0 || number.String() != value {
		return nil, fmt.Errorf("%w: %s must be a canonical non-negative decimal string", ErrConfig, name)
	}
	return number, nil
}

// MarshalJSON uses decimal strings for full-width chain identity and heights.
func (c ObservationConfig) MarshalJSON() ([]byte, error) {
	if c.Policy.ChainID == nil {
		return nil, ErrConfig
	}
	return json.Marshal(observationJSON{c.Policy.ChainID.String(), c.Policy.GenesisHash, c.Policy.Activation.String(), c.Retention.String(), c.Policy.Window, observationCodecJSON{c.Policy.Codec.ExtraBytes, c.Policy.Codec.Proofs, c.Policy.Codec.SettlementRows, c.Policy.Codec.Validators}, c.Policy.StateBytes, c.Policy.CheckpointBytes, c.Policy.AddressRows, c.HistoryWalk, c.ReplayHeaders, c.WitnessItems, c.WitnessBytes, c.WitnessChecksPerStep})
}

// UnmarshalJSON refuses omitted, unknown or non-canonical policy values. It
// never substitutes a production activation, retention or capacity default.
func (c *ObservationConfig) UnmarshalJSON(data []byte) error {
	var input observationJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrConfig
	}
	chainID, err := observationNatural("chainId", input.ChainID)
	if err != nil {
		return err
	}
	activation, err := observationNatural("activation", input.Activation)
	if err != nil {
		return err
	}
	retention, err := observationNatural("retention", input.Retention)
	if err != nil {
		return err
	}
	result := ObservationConfig{Policy: window.Config{ChainID: chainID, GenesisHash: input.GenesisHash, Activation: types.MustHeightFromBig(activation), Window: input.Window, Codec: wire.Limits{ExtraBytes: input.Codec.ExtraBytes, Proofs: input.Codec.Proofs, SettlementRows: input.Codec.SettlementRows, Validators: input.Codec.Validators}, StateBytes: input.StateBytes, CheckpointBytes: input.CheckpointBytes, AddressRows: input.AddressRows}, Retention: types.MustHeightFromBig(retention), HistoryWalk: input.HistoryWalk, ReplayHeaders: input.ReplayHeaders, WitnessItems: input.WitnessItems, WitnessBytes: input.WitnessBytes, WitnessChecksPerStep: input.WitnessChecksPerStep}
	wrapper := Config{Observation: &result, Journal: JournalConfig{Disabled: true}}
	if err := freezeObservation(&wrapper); err != nil {
		return err
	}
	*c = *wrapper.Observation
	return nil
}
