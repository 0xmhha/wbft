package sim

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

func TestDirectedPartitionDelivery(t *testing.T) {
	keys := testValidators(t, 4)
	s, err := newSimulation(Scenario{Validators: keys, DefaultLink: Link{Delay: []time.Duration{time.Millisecond}}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := s.sc.Validators[0].Address(), s.sc.Validators[1].Address()
	s.sc.Partitions = []Partition{{From: time.Second, To: 2 * time.Second, DirectedCut: [][2]types.Address{{a, b}}}}
	ab, ba := 0, 0
	send := func() { s.deliverAfter(a, b, func() { ab++ }); s.deliverAfter(b, a, func() { ba++ }) }
	send()
	s.l.runAt(time.Millisecond)
	if ab != 1 || ba != 1 {
		t.Fatalf("before: %d/%d", ab, ba)
	}
	s.l.runAt(time.Second)
	send()
	s.l.runAt(time.Second + time.Millisecond)
	if ab != 1 || ba != 2 {
		t.Fatalf("during: %d/%d", ab, ba)
	}
	s.l.runAt(2 * time.Second)
	send()
	s.l.runAt(2*time.Second + time.Millisecond)
	if ab != 2 || ba != 3 {
		t.Fatalf("after: %d/%d", ab, ba)
	}
	// The existing cut remains symmetric.
	s.sc.Partitions = []Partition{{From: 2 * time.Second, To: 3 * time.Second, Cut: [][2]types.Address{{a, b}}}}
	send()
	s.l.runAt(2*time.Second + 2*time.Millisecond)
	if ab != 2 || ba != 3 {
		t.Fatalf("symmetric: %d/%d", ab, ba)
	}
}

func TestDirectedPartitionCancelsInFlight(t *testing.T) {
	s, err := newSimulation(Scenario{Validators: testValidators(t, 4), DefaultLink: Link{Delay: []time.Duration{2 * time.Second}}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := s.sc.Validators[0].Address(), s.sc.Validators[1].Address()
	s.sc.Partitions = []Partition{{From: time.Second, To: 3 * time.Second, DirectedCut: [][2]types.Address{{a, b}}}}
	ab, ba := false, false
	s.deliverAfter(a, b, func() { ab = true })
	s.deliverAfter(b, a, func() { ba = true })
	s.l.runAt(2 * time.Second)
	if ab || !ba {
		t.Fatalf("in flight: %v/%v", ab, ba)
	}
}

func TestScenarioProposerPolicy(t *testing.T) {
	for _, policy := range []uint64{0, types.Sticky} {
		res, err := Run(context.Background(), Scenario{Validators: testValidators(t, 4), Params: Params{ProposerPolicy: policy}, Until: Stop{Height: 4, Duration: time.Minute}}, Output{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Violations) > 0 || len(res.Chain) != 5 {
			t.Fatalf("policy %d: chain=%d violations=%v", policy, len(res.Chain), res.Violations)
		}
		for i := 2; i < len(res.Chain); i++ {
			same := types.ProposerOf(res.Chain[i].Header) == types.ProposerOf(res.Chain[i-1].Header)
			if same != (policy == types.Sticky) {
				t.Fatalf("policy %d at height %d: same=%v", policy, i, same)
			}
		}
	}
}

func TestPartitionRejectsInvalidEvidence(t *testing.T) {
	keys := testValidators(t, 4)
	a, err := NewValidator(keys[0].ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewValidator(keys[1].ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Partition{
		{From: -1, To: time.Second},
		{From: time.Second, To: time.Second},
		{From: 0, To: time.Second, DirectedCut: [][2]types.Address{{a.Address(), a.Address()}}},
		{From: 0, To: time.Second, DirectedCut: [][2]types.Address{{a.Address(), {}}}},
		{From: 0, To: time.Second, Cut: [][2]types.Address{{{}, b.Address()}}},
	} {
		_, err := Run(context.Background(), Scenario{Validators: keys, Partitions: []Partition{p}}, Output{})
		if !errors.Is(err, ErrScenario) {
			t.Fatalf("accepted invalid partition: %v", err)
		}
	}
}
