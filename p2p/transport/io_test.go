package transport

import (
	"testing"

	"github.com/0xmhha/wbft/types"
)

type ioReports struct {
	closedOnly
	received, wrote, captured int
	capture                   uint64
	interval                  IOInterval
}

func (o *ioReports) Received(types.Address, uint64, int, []byte, string) { o.received++ }
func (o *ioReports) Wrote(types.Address, uint64, []byte, string)         { o.wrote++ }
func (o *ioReports) Capture() uint64                                     { return 7 }
func (o *ioReports) ReceivedCapture(_ types.Address, _ uint64, _ int, _ []byte, _ string, c uint64) {
	o.captured++
	o.capture = c
}

type timedReports struct {
	ioReports
	timedRead, timedWrite int
}

func (o *timedReports) Moment() IOMoment { return IOMoment{Mono: 10, WallNs: 11} }
func (o *timedReports) ReceivedIO(_ types.Address, _ uint64, _ int, _ []byte, _ string, c uint64, x IOInterval) {
	o.timedRead++
	o.capture = c
	o.interval = x
}
func (o *timedReports) WroteIO(_ types.Address, _ uint64, _ []byte, _ string, x IOInterval) {
	o.timedWrite++
	o.interval = x
}

func TestIOObserverFallbackAndSingleDelivery(t *testing.T) {
	p := types.Address{1}
	x := IOInterval{Start: IOMoment{Mono: 1}, End: IOMoment{Mono: 2}}
	o := &ioReports{}
	if BeginIO(o) != (IOMoment{}) {
		t.Fatal("legacy observer fabricated I/O clock")
	}
	ReportReceivedIO(o, p, 0x13, 1, []byte{1}, OfferQueued, 7, x)
	ReportWroteIO(o, p, 0x13, []byte{1}, WriteError, x)
	if o.received != 0 || o.captured != 1 || o.wrote != 1 || o.capture != 7 {
		t.Fatal("legacy observer contract changed", o)
	}
	timed := &timedReports{}
	if BeginIO(timed) != (IOMoment{Mono: 10, WallNs: 11}) {
		t.Fatal("observer clock lost")
	}
	ReportReceivedIO(timed, p, 0x13, 1, []byte{1}, OfferQueued, 7, x)
	ReportWroteIO(timed, p, 0x13, []byte{1}, WriteOK, x)
	if timed.timedRead != 1 || timed.timedWrite != 1 || timed.received != 0 || timed.captured != 0 || timed.wrote != 0 || timed.interval != x || timed.capture != 7 {
		t.Fatal("duplicate or changed I/O record", timed)
	}
	ReportReceivedIO(nil, p, 0x13, 0, nil, OfferFrameDisconnect, 0, x)
	ReportWroteIO(nil, p, 0x13, nil, WriteError, x)
}
