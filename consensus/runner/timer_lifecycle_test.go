package runner

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// Clear is the operator-stop boundary used by stopEngine. Advance only the
// normal clock: no expired callback, packet or queue entry is fabricated.
func TestNormalTimerClearSeparatesReservations(t *testing.T) {
	for _, kind := range consensus.SupportedTimers {
		for _, elapsed := range []time.Duration{time.Second, 2 * time.Second} {
			t.Run(fmt.Sprintf("%s/%d", kind, elapsed), func(t *testing.T) {
				clock := &manualClock{}
				q := NewTimerQueue(clock)
				old := consensus.ArmTimer{Kind: kind, View: view(10, 0), Round: types.RoundFromUint64(0), Gen: 1, Duration: 2 * time.Second}
				q.Arm(old, clock.Mono())
				clock.advance(elapsed)
				if q.Pending() != (elapsed == 2*time.Second) {
					t.Fatal("normal expiry boundary was not exercised")
				}
				q.Clear()
				if _, ok := q.Pop(); ok || q.Pending() {
					t.Fatal("stop retained an expiry")
				}
				current := consensus.ArmTimer{Kind: kind, View: view(11, 0), Round: types.RoundFromUint64(0), Gen: 1, Duration: 3 * time.Second}
				q.Arm(current, clock.Mono())
				clock.advance(elapsed + 2*time.Second)
				if _, ok := q.Pop(); ok {
					t.Fatal("old reservation crossed the clear boundary")
				}
				clock.advance(elapsed + 3*time.Second)
				got, ok := q.Pop()
				if !ok || got.Kind != current.Kind || got.View.Cmp(current.View) != 0 || got.Gen != current.Gen {
					t.Fatal("new reservation lost", got, ok)
				}
				if _, ok = q.Pop(); ok {
					t.Fatal("unexpected second expiry")
				}
			})
		}
	}
}
