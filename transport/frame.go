package transport

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// Codes of the istanbul/100 protocol, relative to its offset.
const (
	CodeNewBlock uint64 = 0x07 // NewBlock, no effect on the consensus stream
	CodeLegacy   uint64 = 0x11 // legacy wrapper, unwrapped on receipt
	CodeFirst    uint64 = 0x12 // PRE-PREPARE
	CodeLast     uint64 = 0x15 // ROUND-CHANGE
	// ProtocolLength is the number of codes of istanbul/100.
	ProtocolLength uint64 = 0x16
	// MaxFramePayload is the largest istanbul payload a node reads.
	MaxFramePayload = types.MaxIstanbulMsgSize
)

// FrameAction is the verdict on one received istanbul frame.
type FrameAction uint8

// Frame verdicts.
const (
	// FrameDeliver: hand data under deliverCode to the receive path.
	FrameDeliver FrameAction = iota
	// FrameDrop: discard the frame and keep reading (outcome DROP_SILENT).
	FrameDrop
	// FrameDisconnect: close the connection (outcome DISCONNECT).
	FrameDisconnect
)

// Outcome returns the outcome class of a frame that is not delivered;
// delivered frames are classified by the receive path.
func (a FrameAction) Outcome() event.OutcomeClass {
	switch a {
	case FrameDrop:
		return event.DropSilent
	case FrameDisconnect:
		return event.Disconnect
	}
	return ""
}

func (a FrameAction) String() string {
	switch a {
	case FrameDeliver:
		return "deliver"
	case FrameDrop:
		return "drop"
	case FrameDisconnect:
		return "disconnect"
	}
	return "unknown"
}

// Reasons returned by DecodeFrame.
const (
	ReasonTooLarge     = "too_large"
	ReasonCodeRange    = "code_out_of_range"
	ReasonNotConsensus = "not_consensus"
	ReasonNewBlock     = "new_block"
	ReasonLegacyDecode = "legacy_decode"
	ReasonEmpty        = "empty_payload"
	ReasonEngineStop   = "engine_stopped"
)

// IsConsensusCode reports whether code is one of the codes the consensus
// handler takes: the legacy wrapper and the four message codes.
func IsConsensusCode(code uint64) bool { return code >= CodeLegacy && code <= CodeLast }

// DecodeFrame judges one received istanbul frame with a code relative to the
// protocol offset, in this order: a payload above MaxFramePayload
// disconnects; a code outside the protocol disconnects; codes below 0x11
// (NewBlock included) are dropped; 0x11 is unwrapped from its first RLP byte
// string, and a payload that does not start with one disconnects; codes 0x12
// to 0x15 with an empty payload disconnect; the rest is delivered unchanged.
// reason names the rule for logs.
//
// The engine-stopped rule of the receive path (StoppedEngineAction) applies
// after the size limit and before the other rules.
//
// Spec: WBFT-NET-012, WBFT-NET-013, WBFT-NET-020, WBFT-NET-021, WBFT-NET-028, WBFT-MSG-050
func DecodeFrame(code uint64, payload []byte) (data []byte, deliverCode uint64, act FrameAction, reason string) {
	if len(payload) > MaxFramePayload {
		return nil, 0, FrameDisconnect, ReasonTooLarge
	}
	switch {
	case code >= ProtocolLength:
		return nil, 0, FrameDisconnect, ReasonCodeRange
	case code == CodeNewBlock:
		return nil, 0, FrameDrop, ReasonNewBlock
	case code < CodeLegacy:
		return nil, 0, FrameDrop, ReasonNotConsensus
	case code == CodeLegacy:
		content, _, err := rlp.SplitString(payload)
		if err != nil {
			return nil, 0, FrameDisconnect, ReasonLegacyDecode
		}
		return content, CodeLegacy, FrameDeliver, ""
	}
	if len(payload) == 0 {
		return nil, 0, FrameDisconnect, ReasonEmpty
	}
	return payload, code, FrameDeliver, ""
}

// StoppedEngineAction is the verdict on a frame with a code from 0x11 to 0x15
// that arrives while the consensus core is not running: drop it while the
// node synchronises, disconnect otherwise.
//
// Spec: WBFT-NET-027
func StoppedEngineAction(synchronising bool) FrameAction {
	if synchronising {
		return FrameDrop
	}
	return FrameDisconnect
}

// Errors of CheckOutbound.
var (
	ErrOutboundCode = errors.New("transport: outbound code is not a consensus message code")
	ErrOutboundSize = errors.New("transport: outbound payload exceeds the frame limit")
)

// CheckOutbound checks a message before it is sent: the code is one of 0x12
// to 0x15 (never 0x11) and the payload is not longer than the limit a
// receiver reads.
//
// Spec: WBFT-NET-010, WBFT-NET-011, WBFT-MSG-051
func CheckOutbound(code uint64, payload []byte) error {
	if code < CodeFirst || code > CodeLast {
		return fmt.Errorf("%w: 0x%x", ErrOutboundCode, code)
	}
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("%w: %d bytes", ErrOutboundSize, len(payload))
	}
	return nil
}
