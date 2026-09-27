package main

import (
	"encoding/json"
	"errors"
	"slices"
)

// errUnsupported marks a case whose operation the implementation does not
// provide; the session answers it with status "unsupported".
var errUnsupported = errors.New("unsupported")

// handler computes the output of one case from its converted input. It
// returns errUnsupported when it cannot decide the case, or another error
// when the operation itself fails (status "error").
type handler func(kind string, input json.RawMessage) (output any, err error)

// handlers maps "<runner>/<handler>" to its implementation. The keys are the
// handlers this adapter answers for the consensus layer; handlers of the
// execution layer are answered by other adapters (WBFT-VEC-054).
//
// A nil entry is listed in hello but answered "unsupported". In milestone W0
// every entry is nil.
var handlers = map[string]handler{
	// crypto
	"crypto/keccak256":             nil,
	"crypto/ecdsa_sign":            nil,
	"crypto/ecdsa_recover":         nil,
	"crypto/bls_derive":            nil,
	"crypto/bls_sign":              nil,
	"crypto/bls_verify":            nil,
	"crypto/bls_aggregate":         nil,
	"crypto/aggregate_public_keys": nil,
	"crypto/seal_data":             nil,
	"crypto/randao_data":           nil,
	"crypto/randao_mix":            nil,
	// encoding
	"encoding/extra_codec":     nil,
	"encoding/block_hash":      nil,
	"encoding/hash_with_round": nil,
	"encoding/filtered_header": nil,
	"encoding/message_codec":   nil,
	"encoding/signing_payload": nil,
	"encoding/dedup_key":       nil,
	// validators
	"validators/quorum":          nil,
	"validators/proposer":        nil,
	"validators/epoch_boundary":  nil,
	"validators/validators_at":   nil,
	"validators/shuffle":         nil,
	"validators/sort_candidates": nil,
	"validators/next_epoch_info": nil,
	// timers
	"timers/round_timeout": nil,
	"timers/build_wait":    nil,
	// state machine
	"state_machine/check_message": nil,
	"state_machine/is_justified":  nil,
	"state_machine/rounds":        nil,
	// network: cases decided by consensus code and engine state; cases
	// decided by the transport adapter stay "unsupported" here.
	"network/receive_outcome": nil,
	// header
	"header/build_proposal_header": nil,
	"header/verify_header":         nil,
	"header/verify_headers":        nil,
	"header/verify_light":          nil,
	// chain
	"chain/config_at": nil,
}

// handlerNames returns the keys of handlers in sorted order, for hello.
func handlerNames() []string {
	names := make([]string, 0, len(handlers))
	for name := range handlers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// dispatch runs the handler for "<runner>/<handler>".
func dispatch(name, kind string, input json.RawMessage) (any, error) {
	h := handlers[name]
	if h == nil {
		return nil, errUnsupported
	}
	return h(kind, input)
}
