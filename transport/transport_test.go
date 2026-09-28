package transport

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// One case per row of the frame rules.
//
// Covers: WBFT-MSG-050
func TestDecodeFrame(t *testing.T) {
	msg := []byte{0xc3, 0x01, 0x02, 0x03}
	wrapped := rlp.EncodeString(msg)
	big := make([]byte, MaxFramePayload)
	tests := []struct {
		name    string
		code    uint64
		payload []byte
		act     FrameAction
		deliver uint64
		data    []byte
		reason  string
	}{
		{"consensus code delivered unchanged", 0x13, msg, FrameDeliver, 0x13, msg, ""},
		{"payload of exactly the limit", 0x12, big, FrameDeliver, 0x12, big, ""},
		{"payload one byte above the limit", 0x12, append(big, 0), FrameDisconnect, 0, nil, ReasonTooLarge},
		{"above the limit with another code", 0x07, append(big, 0), FrameDisconnect, 0, nil, ReasonTooLarge},
		{"empty payload", 0x15, nil, FrameDisconnect, 0, nil, ReasonEmpty},
		{"legacy code unwrapped", 0x11, wrapped, FrameDeliver, 0x11, msg, ""},
		{"legacy code, bytes after the first item ignored", 0x11, append(append([]byte{}, wrapped...), 0xaa, 0xbb), FrameDeliver, 0x11, msg, ""},
		{"legacy code, single byte string", 0x11, []byte{0x05}, FrameDeliver, 0x11, []byte{0x05}, ""},
		{"legacy code, list instead of string", 0x11, []byte{0xc1, 0x01}, FrameDisconnect, 0, nil, ReasonLegacyDecode},
		{"legacy code, non-canonical size", 0x11, []byte{0x81, 0x05}, FrameDisconnect, 0, nil, ReasonLegacyDecode},
		{"legacy code, string past the end", 0x11, []byte{0x83, 0x01}, FrameDisconnect, 0, nil, ReasonLegacyDecode},
		{"legacy code, empty payload", 0x11, nil, FrameDisconnect, 0, nil, ReasonLegacyDecode},
		{"NewBlock", 0x07, msg, FrameDrop, 0, nil, ReasonNewBlock},
		{"other code of the protocol", 0x10, []byte{0x80}, FrameDrop, 0, nil, ReasonNotConsensus},
		{"code zero", 0x00, nil, FrameDrop, 0, nil, ReasonNotConsensus},
		{"code outside the protocol", 0x16, msg, FrameDisconnect, 0, nil, ReasonCodeRange},
	}
	for _, tt := range tests {
		data, deliver, act, reason := DecodeFrame(tt.code, tt.payload)
		if act != tt.act || deliver != tt.deliver || !bytes.Equal(data, tt.data) || reason != tt.reason {
			t.Errorf("%s: got (%d bytes, 0x%x, %v, %q), want (%d bytes, 0x%x, %v, %q)",
				tt.name, len(data), deliver, act, reason, len(tt.data), tt.deliver, tt.act, tt.reason)
		}
	}
}

func TestFrameOutcomes(t *testing.T) {
	if FrameDrop.Outcome() != event.DropSilent || FrameDisconnect.Outcome() != event.Disconnect || FrameDeliver.Outcome() != "" {
		t.Fatal("outcome classes")
	}
	if StoppedEngineAction(true) != FrameDrop || StoppedEngineAction(false) != FrameDisconnect {
		t.Fatal("stopped engine rule")
	}
	for c := uint64(0); c < 0x20; c++ {
		if IsConsensusCode(c) != (c >= 0x11 && c <= 0x15) {
			t.Errorf("IsConsensusCode(0x%x)", c)
		}
	}
}

// Covers: WBFT-MSG-051
func TestCheckOutbound(t *testing.T) {
	for code := uint64(0); code < 0x20; code++ {
		err := CheckOutbound(code, []byte{0xc0})
		if ok := code >= 0x12 && code <= 0x15; ok != (err == nil) {
			t.Errorf("code 0x%x: %v", code, err)
		}
	}
	if err := CheckOutbound(0x11, []byte{0xc0}); !errors.Is(err, ErrOutboundCode) {
		t.Errorf("0x11: %v", err)
	}
	if err := CheckOutbound(0x12, make([]byte, MaxFramePayload)); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	if err := CheckOutbound(0x12, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrOutboundSize) {
		t.Errorf("above the limit: %v", err)
	}
}

// fakeTransport records sends and returns a fixed result.
type fakeTransport struct {
	peers  []types.Address
	result SendResult
	sends  []send
}

type send struct {
	peers []types.Address
	code  uint64
}

func (f *fakeTransport) Send(peers []types.Address, code uint64, _ []byte) []SendResult {
	f.sends = append(f.sends, send{append([]types.Address(nil), peers...), code})
	out := make([]SendResult, len(peers))
	for i := range out {
		out[i] = f.result
	}
	return out
}
func (f *fakeTransport) SetReceiver(Receiver)             {}
func (f *fakeTransport) PeerEvents() <-chan PeerEvent     { return nil }
func (f *fakeTransport) Disconnect(types.Address, string) {}
func (f *fakeTransport) Peers() []PeerInfo {
	out := make([]PeerInfo, len(f.peers))
	for i, p := range f.peers {
		out[i] = PeerInfo{Addr: p}
	}
	return out
}

func addr(i int) types.Address { return types.Address{0xa0, byte(i >> 8), byte(i)} }

func set(t *testing.T, as ...types.Address) *validator.Set {
	t.Helper()
	keys := make([][]byte, len(as))
	vs, err := validator.NewSet(as, keys, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func newDedup(t *testing.T, tr Transport, self types.Address) *Dedup {
	t.Helper()
	d, err := NewDedup(tr, DedupOptions{Self: self})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewDedupReservedOptions(t *testing.T) {
	for _, opt := range []DedupOptions{{KeyWithCode: true}, {RecordAfterSend: true}, {Observers: []types.Address{addr(1)}}} {
		if _, err := NewDedup(&fakeTransport{}, opt); !errors.Is(err, ErrReservedOption) {
			t.Errorf("%+v: %v", opt, err)
		}
	}
}

// The recent cache is filled before the known-cache check, and the known
// cache is filled on the first receipt, before the core has seen the message.
func TestSeenInbound(t *testing.T) {
	tr := &fakeTransport{}
	d := newDedup(t, tr, addr(0))
	payload := []byte{0xc1, 0x80}
	if d.SeenInbound(addr(1), 0x13, payload) {
		t.Fatal("first receipt reported as duplicate")
	}
	if !d.Known(payload) || !d.SentOrReceived(addr(1), payload) {
		t.Fatal("key not recorded")
	}
	if !d.SeenInbound(addr(2), 0x13, payload) {
		t.Fatal("second receipt from another peer not dropped")
	}
	if !d.SentOrReceived(addr(2), payload) {
		t.Fatal("the recent cache of the second peer lacks the key")
	}
	// The key is the dedup key of the payload.
	if codec.DedupKey(payload) != codec.DedupKey(append([]byte(nil), payload...)) {
		t.Fatal("key")
	}
}

func TestGossipTargets(t *testing.T) {
	self, v1, v2, v3, other := addr(0), addr(1), addr(2), addr(3), addr(9)
	tr := &fakeTransport{peers: []types.Address{v3, other, v1, self, v2}}
	d := newDedup(t, tr, self)
	vs := set(t, self, v1, v2, v3)
	payload := []byte{0xc2, 0x01, 0x02}

	// A message received from v2 is not sent back to v2; non-validators and
	// the node itself are never targets; targets come in address order.
	d.SeenInbound(v2, 0x13, payload)
	got := d.Gossip(vs, 0x13, payload, event.CauseRelay)
	if want := []types.Address{v1, v3}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("targets %v, want %v", got, want)
	}
	if len(tr.sends) != 1 || tr.sends[0].code != 0x13 {
		t.Fatalf("sends %+v", tr.sends)
	}
	// A second gossip of the same bytes sends nothing.
	if got := d.Gossip(vs, 0x13, payload, event.CauseRelay); len(got) != 0 {
		t.Fatalf("repeat targets %v", got)
	}
	if len(tr.sends) != 1 {
		t.Fatalf("repeat was sent: %+v", tr.sends)
	}
	// Different bytes are sent again.
	if got := d.Gossip(vs, 0x15, []byte{0xc1, 0x03}, event.CauseRetry); len(got) != 3 {
		t.Fatalf("new bytes targets %v", got)
	}
}

// The key is recorded for a peer before the send, whatever its result.
func TestGossipRecordsBeforeSend(t *testing.T) {
	self, v1 := addr(0), addr(1)
	tr := &fakeTransport{peers: []types.Address{v1}, result: NotAttached}
	d := newDedup(t, tr, self)
	vs := set(t, self, v1)
	payload := []byte{0xc1, 0x07}
	if got := d.Gossip(vs, 0x14, payload, event.CauseBroadcast); len(got) != 1 {
		t.Fatalf("targets %v", got)
	}
	if !d.SentOrReceived(v1, payload) {
		t.Fatal("key not recorded after a failed send")
	}
	if got := d.Gossip(vs, 0x14, payload, event.CauseBroadcast); len(got) != 0 {
		t.Fatalf("second gossip targets %v", got)
	}
}

func TestBroadcastRequiresMembership(t *testing.T) {
	self, v1 := addr(0), addr(1)
	tr := &fakeTransport{peers: []types.Address{v1}}
	d := newDedup(t, tr, self)
	if got := d.Broadcast(set(t, v1), 0x13, []byte{0xc0}, event.CauseBroadcast); got != nil || len(tr.sends) != 0 {
		t.Fatalf("non-member sent to %v", got)
	}
	if got := d.Broadcast(set(t, self, v1), 0x13, []byte{0xc0}, event.CauseBroadcast); len(got) != 1 {
		t.Fatalf("member targets %v", got)
	}
	if !d.Known([]byte{0xc0}) {
		t.Fatal("broadcast key not in the known cache")
	}
}

// A code outside the four message codes goes out under the legacy code.
func TestGossipOutboundCode(t *testing.T) {
	self, v1 := addr(0), addr(1)
	tr := &fakeTransport{peers: []types.Address{v1}}
	d := newDedup(t, tr, self)
	d.Gossip(set(t, self, v1), 0x11, []byte{0x01}, event.CauseRelay)
	if len(tr.sends) != 1 || tr.sends[0].code != CodeLegacy {
		t.Fatalf("sends %+v", tr.sends)
	}
}

// LRU bounds: InmemoryMessages keys in the known cache and per peer, and
// InmemoryPeers peers in the recent cache.
func TestCacheBounds(t *testing.T) {
	tr := &fakeTransport{}
	d := newDedup(t, tr, addr(0))
	payload := func(i int) []byte { return []byte{0x82, byte(i >> 8), byte(i)} }
	for i := 0; i < InmemoryMessages; i++ {
		d.SeenInbound(addr(1), 0x13, payload(i))
	}
	if !d.Known(payload(0)) || !d.SentOrReceived(addr(1), payload(0)) {
		t.Fatal("key evicted before the cache was full")
	}
	d.SeenInbound(addr(1), 0x13, payload(InmemoryMessages))
	if d.Known(payload(0)) || d.SentOrReceived(addr(1), payload(0)) {
		t.Fatal("least recently used key not evicted")
	}
	if !d.Known(payload(1)) {
		t.Fatal("wrong key evicted")
	}

	// Peers: the 41st peer evicts the least recently used one.
	for i := 0; i < InmemoryPeers; i++ {
		d.SeenInbound(addr(100+i), 0x13, []byte{0x01})
	}
	if !d.SentOrReceived(addr(100), []byte{0x01}) {
		t.Fatal("peer evicted before the cache was full")
	}
	d.SeenInbound(addr(100+InmemoryPeers), 0x13, []byte{0x01})
	if d.SentOrReceived(addr(100), []byte{0x01}) {
		t.Fatal("least recently used peer not evicted")
	}
}

func TestLRU(t *testing.T) {
	c := newLRU[int, string](2)
	c.Add(1, "a")
	c.Add(2, "b")
	if _, ok := c.Get(1); !ok { // refresh 1
		t.Fatal("1 missing")
	}
	c.Add(3, "c") // evicts 2
	if c.Contains(2) || !c.Contains(1) || !c.Contains(3) || c.Len() != 2 {
		t.Fatal("eviction order")
	}
	c.Add(1, "z")
	if v, _ := c.Get(1); v != "z" {
		t.Fatal("update")
	}
	c.Remove(1)
	if c.Contains(1) || c.Len() != 1 {
		t.Fatal("remove")
	}
}
