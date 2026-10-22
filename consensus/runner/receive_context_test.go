package runner

import (
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestReceiveContextMetadataPreservesAuthorityMeaning(t *testing.T) {
	keys := newKeys(t, 5)
	all := nextHeightSet(t, keys, []int{0, 1, 2, 3, 4})
	original := nextHeightSet(t, keys, []int{0, 1, 2, 3})
	reference, err := receiveAuthorityDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	addresses := original.Addresses()
	public := make([][]byte, original.Len())
	for index := range original.Len() {
		public[index] = original.At(index).BLSPublicKey
	}
	copySet, err := validator.NewSet(addresses, public, original.Policy())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := receiveAuthorityDigest(copySet)
	if err != nil || digest != reference {
		t.Fatal("equivalent immutable set changed digest", err)
	}
	reordered, err := validator.NewSet([]types.Address{addresses[1], addresses[0], addresses[2], addresses[3]}, [][]byte{public[1], public[0], public[2], public[3]}, original.Policy())
	if err != nil {
		t.Fatal(err)
	}
	sticky, err := validator.NewSet(addresses, public, types.ProposerPolicy{ID: types.Sticky})
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeys := append([][]byte(nil), public...)
	rotatedKeys[0] = all.At(4).BLSPublicKey
	rotated, err := validator.NewSet(addresses, rotatedKeys, original.Policy())
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []*validator.Set{reordered, sticky, rotated} {
		digest, err := receiveAuthorityDigest(set)
		if err != nil || digest == reference {
			t.Fatal("order, key rotation or proposer policy lost", err)
		}
	}
	absent, err := receiveAuthorityDigest(nil)
	if err != nil || absent != (types.Hash{}) {
		t.Fatal("absent set inferred", err)
	}
	empty, err := validator.NewSet(nil, nil, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	emptyDigest, err := receiveAuthorityDigest(empty)
	if err != nil || emptyDigest == absent {
		t.Fatal("absent and empty set conflated", err)
	}
	large := new(big.Int).Lsh(big.NewInt(1), 80)
	snapshot := &consensus.Snapshot{Running: true, View: types.View{Sequence: types.MustHeightFromBig(large), Round: types.RoundFromUint64(7)}, State: consensus.Preprepared, PriorRound: types.RoundFromUint64(6), Validators: original, PriorValidators: rotated}
	metadata, available := receiveContextMetadata(snapshot)
	if !available || metadata.Sequence != large.String() || metadata.Round != "7" || metadata.PriorRound != "6" || metadata.State != "Preprepared" || !metadata.ValidatorsPresent || !metadata.PriorValidatorsPresent || metadata.Validators != reference {
		t.Fatal("actual checking context incomplete", metadata)
	}
	scope := transport.NewValidationScopeWithContext(metadata)
	metadata.Sequence = "999"
	frozen, available := scope.Context()
	if !available || frozen.Sequence != large.String() {
		t.Fatal("scope retained mutable caller metadata")
	}
	scope.Close()
	closed, available := scope.Context()
	if !available || closed != frozen {
		t.Fatal("old closed scope lost original context")
	}
	if _, available := transport.NewValidationScope().Context(); available {
		t.Fatal("missing checking context inferred")
	}
	if _, available := receiveContextMetadata(nil); available {
		t.Fatal("missing snapshot inferred")
	}
}
