package stepdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft/consensus"
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

// Pure steps inputs have no ordered validator-lookup availability witness.
// Closed RunTrace journals retain that source and are supported separately.
func TestValidatorStartPureStepsRequireAuthoritySource(t *testing.T) {
	fixture := newFixture(t)
	for _, handler := range []string{HandlerRounds, HandlerReceiveOutcome} {
		network := handler == HandlerReceiveOutcome
		state := ""
		if network {
			state = "running"
		}
		input := fixture.input(network, state, false)
		original, err := Run(handler, input, Options{})
		if err != nil {
			t.Fatal("original default case unavailable", handler, err)
		}
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		for _, mask := range []consensus.ImprovementSet{consensus.ImprovementSet(0).With(consensus.DeferValidatorStart), consensus.ImprovementSet(0).With(consensus.DeferValidatorStart).With(consensus.BindPriorHead), consensus.ImprovementSet(0).With(consensus.BindPriorHead), consensus.KnownImprovements()} {
			result, err := Run(handler, input, Options{Improvements: mask})
			if !errors.Is(err, ErrUnsupported) || result != nil {
				t.Fatal("missing ordered authority source became supported", handler, mask, result, err)
			}
		}
		unchanged, err := Run(handler, input, Options{})
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(unchanged)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("selected refusal changed default bytes", handler, err)
		}
	}
}
