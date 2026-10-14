package runner

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
	"testing"
	"time"
)

func TestRecordedExpiryConsumesOnlyQueuedFullContextWithoutChangingPop(t *testing.T) {
	c := &manualClock{}
	q := NewTimerQueue(c)
	a := consensus.ArmTimer{Kind: consensus.RoundTimer, View: types.View{Sequence: types.HeightFromUint64(10)}, Gen: 2, Duration: 3 * time.Nanosecond}
	b := consensus.ArmTimer{Kind: consensus.RetryTimer, View: a.View, Gen: 3, Duration: 2 * time.Nanosecond}
	q.Arm(a, 0)
	q.Arm(b, 0)
	expected := consensus.Timeout{Kind: a.Kind, View: a.View, Gen: a.Gen}
	if _, ok, err := q.PopRecorded(expected); err != nil || ok {
		t.Fatal("unfired timer manufactured", ok, err)
	}
	c.advance(10 * time.Nanosecond)
	wrong := expected
	wrong.View.Round = types.RoundFromUint64(1)
	if _, ok, err := q.PopRecorded(wrong); err != nil || ok {
		t.Fatal("different context consumed", ok, err)
	}
	if got, ok, err := q.PopRecorded(expected); err != nil || !ok || got.Gen != a.Gen {
		t.Fatal(got, ok, err)
	}
	if got, ok := q.Pop(); !ok || got.Kind != b.Kind || got.Gen != b.Gen {
		t.Fatal("remaining order changed", got, ok)
	}
	if _, ok, err := q.PopRecorded(expected); err != nil || ok {
		t.Fatal("expiry reused", ok, err)
	}
}
