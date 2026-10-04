package devnet

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type recv struct {
	mu  sync.Mutex
	got []transport.Inbound
}

func (r *recv) Offer(in transport.Inbound) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, in)
	return true
}

func (r *recv) wait(t *testing.T, n int) []transport.Inbound {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		if len(r.got) >= n {
			out := append([]transport.Inbound(nil), r.got...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("received fewer than %d messages", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pair starts two connected transports.
func pair(t *testing.T) (a, b *Transport, ra, rb *recv) {
	t.Helper()
	aa, ab := types.Address{1}, types.Address{2}
	b, err := New(Config{Self: ab, Listen: "127.0.0.1:0", Network: "test", Peers: []Peer{{Addr: aa}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	a, err = New(Config{Self: aa, Listen: "127.0.0.1:0", Network: "test", Peers: []Peer{{Addr: ab, Endpoint: b.Endpoint()}},
		RedialInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ra, rb = &recv{}, &recv{}
	a.SetReceiver(ra)
	b.SetReceiver(rb)
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	waitPeer(t, a, ab)
	waitPeer(t, b, aa)
	return a, b, ra, rb
}

func waitPeer(t *testing.T, tr *Transport, p types.Address) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, pi := range tr.Peers() {
			if pi.Addr == p {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%x did not attach", p)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSendAndReceive(t *testing.T) {
	a, b, _, rb := pair(t)
	bAddr := types.Address{2}
	if res := a.Send([]types.Address{bAddr, {9}}, transport.CodeFirst, []byte("pre-prepare")); res[0] != transport.Queued || res[1] != transport.NotAttached {
		t.Fatalf("send results %v", res)
	}
	got := rb.wait(t, 1)
	if got[0].Peer != (types.Address{1}) || got[0].Code != transport.CodeFirst || !bytes.Equal(got[0].Payload, []byte("pre-prepare")) {
		t.Fatalf("received %+v", got[0])
	}

	// The application channel does not reach the consensus receiver.
	appGot := make(chan []byte, 1)
	b.SetAppHandler(func(peer types.Address, code uint64, payload []byte) {
		if peer == (types.Address{1}) && code == 7 {
			appGot <- payload
		}
	})
	a.SendApp([]types.Address{bAddr}, 7, []byte("block"))
	select {
	case p := <-appGot:
		if string(p) != "block" {
			t.Fatalf("app payload %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no app message")
	}
	if n := len(rb.wait(t, 1)); n != 1 {
		t.Fatalf("consensus receiver got %d messages", n)
	}
}

// TestFrameStage: a frame the frame stage rejects closes the connection,
// and the dialing side connects again.
func TestFrameStage(t *testing.T) {
	a, b, _, rb := pair(t)
	bAddr := types.Address{2}
	// An empty PRE-PREPARE disconnects (DecodeFrame).
	a.Send([]types.Address{bAddr}, transport.CodeFirst, nil)
	deadline := time.Now().Add(5 * time.Second)
	for sawDetach := false; !sawDetach; {
		select {
		case e := <-b.PeerEvents():
			sawDetach = !e.Attached
		case <-time.After(time.Until(deadline)):
			t.Fatal("the connection was not closed")
		}
	}
	waitPeer(t, a, bAddr)
	waitPeer(t, b, types.Address{1})
	// Sends may race with the redial; retry until one is queued.
	for a.Send([]types.Address{bAddr}, transport.CodeLast, []byte("rc"))[0] != transport.Queued {
		time.Sleep(10 * time.Millisecond)
	}
	if got := rb.wait(t, 1); got[0].Code != transport.CodeLast {
		t.Fatalf("received %+v", got[0])
	}
}

// TestHandshake refuses peers of another network and unknown peers.
func TestHandshake(t *testing.T) {
	b, err := New(Config{Self: types.Address{2}, Listen: "127.0.0.1:0", Network: "test", Peers: []Peer{{Addr: types.Address{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, c := range []Config{
		{Self: types.Address{1}, Network: "other"},
		{Self: types.Address{3}, Network: "test"},
	} {
		c.Listen = "127.0.0.1:0"
		c.Peers = []Peer{{Addr: types.Address{4}, Endpoint: b.Endpoint()}}
		a, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if len(b.Peers()) != 0 || len(a.Peers()) != 0 {
			t.Fatalf("%+v attached", c)
		}
		_ = a.Close()
	}
}

// obs records what a transport reports to its frame observer.
type obs struct {
	mu  sync.Mutex
	got []string
}

func (o *obs) add(s string) {
	o.mu.Lock()
	o.got = append(o.got, s)
	o.mu.Unlock()
}

func (o *obs) Received(peer types.Address, code uint64, size int, payload []byte, offer string) {
	if size != len(payload) {
		offer += fmt.Sprintf(" size %d", size)
	}
	o.add(fmt.Sprintf("in %x %#x %q %s", peer[:1], code, payload, offer))
}

func (o *obs) Wrote(peer types.Address, code uint64, payload []byte, write string) {
	o.add(fmt.Sprintf("out %x %#x %q %s", peer[:1], code, payload, write))
}

func (o *obs) Attached(peer types.Address, remote string) {
	o.add(fmt.Sprintf("attached %x %t", peer[:1], remote != ""))
}

func (o *obs) Closed(peer types.Address, reason string) {
	o.add(fmt.Sprintf("closed %x %s", peer[:1], reason))
}

// wait returns the reports once all of want are among them.
func (o *obs) wait(t *testing.T, want ...string) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		o.mu.Lock()
		got := append([]string(nil), o.got...)
		o.mu.Unlock()
		missing := ""
		for _, w := range want {
			if !slices.Contains(got, w) {
				missing = w
				break
			}
		}
		if missing == "" {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("no report %q in %q", missing, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFrameObserver: the transport reports every consensus frame it reads
// with what it did with it, every consensus frame it writes, and the peer
// streams; application frames are not reported.
func TestFrameObserver(t *testing.T) {
	a, b, _, rb := pair(t)
	oa, ob := &obs{}, &obs{}
	a.SetFrameObserver(oa)
	b.SetFrameObserver(ob)
	bAddr := types.Address{2}

	a.Send([]types.Address{bAddr}, transport.CodeFirst, []byte("pre-prepare"))
	rb.wait(t, 1)
	ob.wait(t, `in 01 0x12 "pre-prepare" queued`)
	oa.wait(t, `out 02 0x12 "pre-prepare" ok`)

	// A frame the frame stage drops, an application frame, and one that
	// closes the connection; the dialing side attaches again.
	a.Send([]types.Address{bAddr}, 0x01, []byte("status"))
	a.SendApp([]types.Address{bAddr}, 7, []byte("block"))
	a.Send([]types.Address{bAddr}, transport.CodeFirst, nil)
	ob.wait(t, `in 01 0x1 "status" frame_ignore`, `in 01 0x12 "" frame_disconnect`, "closed 01 read", "attached 01 true")
	got := oa.wait(t, "closed 02 read", "attached 02 true")
	for _, s := range append(got, ob.got...) {
		if strings.Contains(s, "block") {
			t.Fatalf("application frame reported: %q", s)
		}
	}

	// Without an observer nothing is reported.
	b.SetFrameObserver(nil)
	n := len(ob.wait(t))
	for a.Send([]types.Address{bAddr}, transport.CodeLast, []byte("rc"))[0] != transport.Queued {
		time.Sleep(10 * time.Millisecond)
	}
	rb.wait(t, 2)
	if m := len(ob.wait(t)); m != n {
		t.Fatalf("%d reports after the observer was removed", m-n)
	}
}
