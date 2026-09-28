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
// A nil entry is not announced in hello and its cases are answered
// "unsupported": the handlers of the consensus core (state machine, network,
// build wait) come with milestone W2.
var handlers = map[string]handler{
	// crypto
	"crypto/keccak256":             hKeccak256,
	"crypto/ecdsa_sign":            hEcdsaSign,
	"crypto/ecdsa_recover":         hEcdsaRecover,
	"crypto/bls_derive":            hBLSDerive,
	"crypto/bls_sign":              hBLSSign,
	"crypto/bls_verify":            hBLSVerify,
	"crypto/bls_aggregate":         hBLSAggregate,
	"crypto/aggregate_public_keys": hAggregatePublicKeys,
	"crypto/seal_data":             hSealData,
	"crypto/randao_data":           hRandaoData,
	"crypto/randao_mix":            hRandaoMix,
	// encoding
	"encoding/extra_codec":     hExtraCodec,
	"encoding/block_hash":      hBlockHash,
	"encoding/hash_with_round": hHashWithRound,
	"encoding/filtered_header": hFilteredHeader,
	"encoding/message_codec":   hMessageCodec,
	"encoding/signing_payload": hSigningPayload,
	"encoding/dedup_key":       hDedupKey,
	// validators
	"validators/quorum":          hQuorum,
	"validators/proposer":        hProposer,
	"validators/epoch_boundary":  hEpochBoundary,
	"validators/validators_at":   hValidatorsAt,
	"validators/shuffle":         hShuffle,
	"validators/sort_candidates": hSortCandidates,
	"validators/next_epoch_info": hNextEpochInfo,
	// timers
	"timers/round_timeout": hRoundTimeout,
	"timers/build_wait":    nil,
	// state machine
	"state_machine/check_message": nil,
	"state_machine/is_justified":  nil,
	"state_machine/rounds":        nil,
	// network: cases decided by consensus code and engine state; cases
	// decided by the transport adapter stay "unsupported" here.
	"network/receive_outcome": nil,
	// header
	"header/build_proposal_header": hBuildProposalHeader,
	"header/verify_header":         hVerifyHeader,
	"header/verify_headers":        hVerifyHeaders,
	"header/verify_light":          hVerifyLight,
	// chain
	"chain/config_at": hConfigAt,
}

// handlerNames returns, in sorted order, the handlers this adapter
// implements: the keys of handlers with a non-nil entry. hello announces only
// these; a case of any other handler is answered "unsupported".
func handlerNames() []string {
	names := make([]string, 0, len(handlers))
	for name, h := range handlers { //wbft:unordered the names are sorted below
		if h != nil {
			names = append(names, name)
		}
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
