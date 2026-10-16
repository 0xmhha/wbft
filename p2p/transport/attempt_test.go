package transport

import (
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"reflect"
	"testing"
)

type attemptProbe struct {
	FrameObserver
	owner    *AttemptOwner
	got      SendAttempt
	interval *IOInterval
}

func (p *attemptProbe) AttemptOwner() *AttemptOwner { return p.owner }
func (p *attemptProbe) WroteAttempt(_ types.Address, _ uint64, _ []byte, _ string, a SendAttempt, i *IOInterval) {
	p.got, p.interval = a, i
}

func TestAttemptOwnershipAndUnavailable(t *testing.T) {
	if reflect.TypeOf(AttemptOwner{}).Size() == 0 {
		t.Fatal("opaque owner must have nonzero size for pointer identity")
	}

	old, next := NewAttemptOwner(), NewAttemptOwner()
	if old == next {
		t.Fatal("owners alias")
	}
	a := NewSendAttempt(old, 7, 3, 8, event.CauseRetry)
	if !a.OwnedBy(old) || a.OwnedBy(next) {
		t.Fatal("owner mismatch")
	}
	probe := &attemptProbe{owner: old}
	interval := &IOInterval{}
	ReportWroteAttempt(probe, types.Address{1}, CodeFirst, []byte{1}, WriteOK, a, interval)
	if probe.got != a || probe.interval != interval {
		t.Fatal("attempt or timing changed")
	}
	probe.owner = next
	ReportWroteAttempt(probe, types.Address{1}, CodeFirst, []byte{1}, WriteOK, a, nil)
	if probe.got != (SendAttempt{}) || probe.interval != nil {
		t.Fatal("old attempt transferred")
	}
	for _, invalid := range []SendAttempt{NewSendAttempt(nil, 1, 0, 0, ""), NewSendAttempt(old, 0, 0, 0, ""), NewSendAttempt(old, 1, 2, 0, ""), NewSendAttempt(old, 1, 0, 2, "")} {
		if invalid != (SendAttempt{}) {
			t.Fatal("invalid identity accepted", invalid)
		}
	}
}
