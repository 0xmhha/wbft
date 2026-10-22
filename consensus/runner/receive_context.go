package runner

import (
	"crypto/sha256"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type receiveAuthorityMember struct {
	Address    types.Address
	KeyPresent uint64
	Key        []byte
}
type receiveAuthorityEncoding struct {
	Domain  string
	Policy  uint64
	Members []receiveAuthorityMember
}

// receiveAuthorityDigest preserves order, proposer policy and nil key presence.
// It hashes the original immutable set and never serializes a process pointer.
// The encoding is SHA-256(RLP([domain, policy, [[address, key-present, key], ...]])).
func receiveAuthorityDigest(set *validator.Set) (types.Hash, error) {
	if set == nil {
		return types.Hash{}, nil
	}
	encoded := receiveAuthorityEncoding{Domain: "wbft/receive-authority/v1", Policy: set.Policy().ID, Members: make([]receiveAuthorityMember, set.Len())}
	for index := range set.Len() {
		member := set.At(index)
		item := receiveAuthorityMember{Address: member.Addr, Key: member.BLSPublicKey}
		if member.BLSPublicKey != nil {
			item.KeyPresent = 1
		}
		encoded.Members[index] = item
	}
	raw, err := rlp.Encode(&encoded)
	if err != nil {
		return types.Hash{}, err
	}
	return sha256.Sum256(raw), nil
}

func receiveContextMetadata(snapshot *consensus.Snapshot) (transport.ValidationContext, bool) {
	if snapshot == nil || !snapshot.Running {
		return transport.ValidationContext{}, false
	}
	current, err := receiveAuthorityDigest(snapshot.Validators)
	if err != nil {
		return transport.ValidationContext{}, false
	}
	prior, err := receiveAuthorityDigest(snapshot.PriorValidators)
	if err != nil {
		return transport.ValidationContext{}, false
	}
	return transport.ValidationContext{Sequence: snapshot.View.Sequence.String(), Round: snapshot.View.Round.String(), State: snapshot.State.String(), PriorRound: snapshot.PriorRound.String(), Validators: current, PriorValidators: prior, ValidatorsPresent: snapshot.Validators != nil, PriorValidatorsPresent: snapshot.PriorValidators != nil}, true
}

func (r *Runner) newReceiveScope(snapshot *consensus.Snapshot) *transport.ValidationScope {
	// Plain functional caching does not hash authority sets for an absent trace.
	if r.cfg.ReceiveCache == nil || r.cfg.ReceiveCache.Trace == nil {
		return transport.NewValidationScope()
	}
	if context, available := receiveContextMetadata(snapshot); available {
		return transport.NewValidationScopeWithContext(context)
	}
	return transport.NewValidationScope()
}
