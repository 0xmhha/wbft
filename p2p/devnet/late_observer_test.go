package devnet

import (
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
	"strings"
	"testing"
)

func TestLateObserverGetsPeerIdentityBeforeFirstFrame(t *testing.T) {
	a, b, _, rb := pair(t)
	first, second := &obs{}, &obs{}
	a.SetFrameObserver(first)
	b.SetFrameObserver(second)
	if r := a.Send([]types.Address{{2}}, transport.CodeFirst+1, []byte("late-observer")); r[0] != transport.Queued {
		t.Fatal(r)
	}
	rb.wait(t, 1)
	sent := first.wait(t, `out 02 0x13 "late-observer" ok`)
	received := second.wait(t, `in 01 0x13 "late-observer" queued`)
	if len(sent) < 2 || !strings.HasPrefix(sent[0], "attached 02 ") {
		t.Fatal("late outgoing observer lacks its peer identity before the frame", sent)
	}
	if len(received) < 2 || !strings.HasPrefix(received[0], "attached 01 ") {
		t.Fatal("late incoming observer lacks its peer identity before the frame", received)
	}
}
