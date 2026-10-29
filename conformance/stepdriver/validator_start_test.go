package stepdriver

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

func TestValidatorStartRawTraceRequiresAmbiguousKeyWitness(t *testing.T) {
	for _, key := range [][]byte{nil, {}} {
		vs, err := validator.NewSet([]types.Address{{1}}, [][]byte{key}, types.ProposerPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		call := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: types.HeightFromUint64(10), Key: types.Hash{1}, Validators: vs}
		env := &traceEnv{priorProfile: true, requireKeyWitness: true, authorities: []inputlog.EnvCall{call}}
		if _, err := env.ValidatorsAt(call.Number, call.Key); !errors.Is(err, ErrUnsupported) {
			t.Fatal("ambiguous raw key was reported as fully supported", err)
		}
		legacy := &traceEnv{priorProfile: true, authorities: []inputlog.EnvCall{call}}
		if _, err := legacy.ValidatorsAt(call.Number, call.Key); err != nil {
			t.Fatal("legacy trace changed", err)
		}
	}
}
