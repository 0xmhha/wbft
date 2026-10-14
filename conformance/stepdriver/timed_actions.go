package stepdriver

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// TimedOutputSource identifies a one-based output in a verified original step.
type TimedOutputSource struct {
	Source TimedSource `json:"source_input"`
	Output string      `json:"output"`
}

// TimedAction describes an actual output without exporting bytes or block
// hashes. EligibleRecipients is membership intent, not evidence of delivery.
type TimedAction struct {
	Index              string             `json:"output"`
	Kind               string             `json:"kind"`
	SHA256             string             `json:"output_sha256"`
	Height             *string            `json:"height,omitempty"`
	Round              *string            `json:"round,omitempty"`
	Code               string             `json:"code,omitempty"`
	Event              string             `json:"event,omitempty"`
	Timer              string             `json:"timer,omitempty"`
	Duration           *string            `json:"duration_ns,omitempty"`
	CancelKinds        []string           `json:"cancel_kinds,omitempty"`
	EligibleRecipients []string           `json:"eligible_recipients"`
	RecipientEvidence  string             `json:"recipient_evidence"`
	PayloadSHA256      string             `json:"payload_sha256,omitempty"`
	PayloadEvidence    string             `json:"payload_evidence"`
	SigningInput       *TimedSource       `json:"signing_input,omitempty"`
	SigningOutput      *TimedOutputSource `json:"signing_output,omitempty"`
	ApplicationSource  *TimedOutputSource `json:"application_question,omitempty"`
}

func timedRecipients(set *validator.Set, self types.Address) []string {
	out := []string{}
	if set != nil {
		for _, address := range set.Addresses() {
			if address != self {
				out = append(out, strings.ToLower(address.Hex()))
			}
		}
	}
	return out
}
func actionHash(raw []byte) string { hash := sha256.Sum256(raw); return hex.EncodeToString(hash[:]) }
func timedActions(outputs []consensus.Output, self types.Address) ([]TimedAction, error) {
	actions := make([]TimedAction, 0, len(outputs))
	for index, output := range outputs {
		raw, err := inputlog.EncodeOutputs([]consensus.Output{output})
		if err != nil {
			return nil, err
		}
		action := TimedAction{Index: strconv.Itoa(index + 1), SHA256: actionHash(raw), PayloadEvidence: "not_network", RecipientEvidence: "not_network", EligibleRecipients: []string{}}
		view := func(height types.Height, round types.Round) {
			h, r := height.String(), round.String()
			action.Height, action.Round = &h, &r
		}
		switch output := output.(type) {
		case consensus.Broadcast:
			if output.Msg == nil {
				return nil, ErrTraceInvalidInput
			}
			action.Kind = "broadcast"
			action.Code = strconv.FormatUint(uint64(output.Msg.Code), 10)
			view(output.Msg.View.Sequence, output.Msg.View.Round)
			action.EligibleRecipients = timedRecipients(output.Validators, self)
			action.RecipientEvidence = "validator_set"
			if output.Validators == nil {
				action.RecipientEvidence = "unknown"
			}
			action.PayloadEvidence = "unsigned_request"
		case consensus.Relay:
			action.Kind = "relay"
			action.Code = strconv.FormatUint(uint64(output.Code), 10)
			action.EligibleRecipients = timedRecipients(output.Validators, self)
			action.RecipientEvidence = "validator_set"
			if output.Validators == nil {
				action.RecipientEvidence = "unknown"
			}
			action.PayloadSHA256 = actionHash(output.Payload)
			action.PayloadEvidence = "core_relay_bytes"
		case consensus.Schedule:
			action.Kind = "schedule"
		case consensus.ArmTimer:
			action.Kind = "arm_timer"
			action.Timer = strconv.FormatUint(uint64(output.Kind), 10)
			view(output.View.Sequence, output.View.Round)
			duration := strconv.FormatInt(int64(output.Duration), 10)
			action.Duration = &duration
		case consensus.CancelTimers:
			action.Kind = "cancel_timers"
			action.CancelKinds = []string{}
			for _, kind := range output.Kinds {
				action.CancelKinds = append(action.CancelKinds, strconv.FormatUint(uint64(kind), 10))
			}
		case consensus.RequestBuild:
			action.Kind = "request_build"
			view(output.Height, output.Round)
		case consensus.Commit:
			if output.Block == nil || output.Block.Header == nil {
				return nil, ErrTraceInvalidInput
			}
			action.Kind = "commit"
			view(output.Block.Header.Number, output.Round)
		case consensus.Outcome:
			action.Kind = "outcome"
			action.Code = strconv.FormatUint(uint64(output.Code), 10)
			view(output.View.Sequence, output.View.Round)
		case consensus.Event:
			action.Kind = "event"
			action.Event = string(output.Record.Kind)
		default:
			return nil, ErrTraceInvalidInput
		}
		actions = append(actions, action)
	}
	return actions, nil
}
func (action *TimedAction) signed(proof timedSigningEvidence, origin timedOutputKey) {
	input := proof.Source
	action.SigningInput = &input
	action.SigningOutput = &TimedOutputSource{Source: origin.Source, Output: strconv.Itoa(origin.Output + 1)}
	switch value := proof.Input.(type) {
	case consensus.Message:
		action.PayloadEvidence = "recorded_signing_result"
		action.PayloadSHA256 = actionHash(value.Payload)
	case consensus.BroadcastFailed:
		action.PayloadEvidence = "recorded_signing_failure"
	}
}
