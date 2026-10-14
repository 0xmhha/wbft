package node

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestFrameRecorderPreservesIOAndCaptureWithoutInventingTiming(t *testing.T) {
	jw := &memJournal{}
	f := newFrameRecorder(jw, fixedClock{}, 0)
	p := types.Address{1}
	x := transport.IOInterval{Start: transport.IOMoment{Mono: 0, WallNs: 11e9}, End: transport.IOMoment{Mono: time.Second, WallNs: 10e9}}
	f.ReceivedIO(p, 0x13, 1, []byte{1}, transport.OfferQueued, 7, x)
	f.WroteIO(p, 0x13, []byte{1}, transport.WriteError, x)
	f.Wrote(p, 0x13, []byte{1}, transport.WriteNotAttached)
	for i := 0; i < 2; i++ {
		m := jw.recs[i].Body.(*journal.MsgRec)
		if m.Mono != 5*time.Second || m.WallNs != 10e9 || m.IO == nil || m.IO.StartMono != 0 || m.IO.EndMono != time.Second || m.IO.StartWallNs != 11e9 || m.IO.EndWallNs != 10e9 {
			t.Fatal("endpoint replaced by callback clock", m)
		}
	}
	if jw.recs[0].Body.(*journal.MsgRec).Capture != 7 || jw.recs[1].Body.(*journal.MsgRec).Write != transport.WriteError || jw.recs[2].Body.(*journal.MsgRec).IO != nil {
		t.Fatal("capture/result or absent timing changed")
	}
	if f.Moment().Mono != 5*time.Second || f.Moment().WallNs != 10e9 {
		t.Fatal("different monotonic clock origin")
	}
}
