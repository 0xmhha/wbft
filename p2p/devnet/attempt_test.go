package devnet

import (
	"bytes"
	"encoding/binary"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
	"io"
	"net"
	"testing"
	"time"
)

type attemptReport struct {
	attempt transport.SendAttempt
	result  string
	payload []byte
}
type queueObserver struct {
	obs
	owner   *transport.AttemptOwner
	reports chan attemptReport
}

func (o *queueObserver) AttemptOwner() *transport.AttemptOwner { return o.owner }
func (o *queueObserver) WroteAttempt(_ types.Address, _ uint64, p []byte, s string, a transport.SendAttempt, _ *transport.IOInterval) {
	o.reports <- attemptReport{a, s, bytes.Clone(p)}
}

func TestQueuedAttemptSurvivesOnlyItsObserverGeneration(t *testing.T) {
	for _, mode := range []string{"same", "replaced", "reinstalled", "unobserved", "foreign", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			tr, err := New(Config{Listen: "127.0.0.1:0"})
			if err != nil {
				t.Fatal(err)
			}
			owner := transport.NewAttemptOwner()
			old := &queueObserver{owner: owner, reports: make(chan attemptReport, 1)}
			next := &queueObserver{owner: transport.NewAttemptOwner(), reports: make(chan attemptReport, 1)}
			if mode != "unobserved" {
				tr.SetFrameObserver(old)
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			p := types.Address{7}
			c := &conn{peer: p, c: local, out: make(chan frame, 1), gone: make(chan struct{})}
			tr.peers[p] = c
			a := transport.NewSendAttempt(owner, 11, 2, 8, event.CauseRetry)
			if mode == "foreign" {
				a = transport.NewSendAttempt(next.owner, 11, 2, 8, event.CauseRetry)
			}
			payload := []byte("same transmitted bytes")
			var res []transport.SendResult
			if mode == "legacy" {
				res = tr.Send([]types.Address{p, {9}}, 0x13, payload)
			} else {
				res = tr.SendAttempt([]types.Address{p, {9}}, 0x13, payload, a)
			}
			if len(res) != 2 || res[0] != transport.Queued || res[1] != transport.NotAttached {
				t.Fatal(res)
			}
			if got := tr.SendAttempt([]types.Address{p}, 0x13, payload, a); got[0] != transport.QueueFull {
				t.Fatal("queue capacity changed", got)
			}
			observer := old
			switch mode {
			case "replaced":
				tr.SetFrameObserver(next)
				observer = next
			case "reinstalled":
				tr.SetFrameObserver(next)
				tr.SetFrameObserver(old)
			case "unobserved":
				tr.SetFrameObserver(old)
			}
			done := make(chan struct{})
			go func() { defer close(done); tr.writeLoop(c) }()
			want := []byte{chanConsensus}
			want = binary.AppendUvarint(want, 0x13)
			want = binary.AppendUvarint(want, uint64(len(payload)))
			want = append(want, payload...)
			_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
			got := make([]byte, len(want))
			if _, err := io.ReadFull(remote, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("metadata changed wire bytes")
			}
			select {
			case report := <-observer.reports:
				if report.result != transport.WriteOK || !bytes.Equal(report.payload, payload) {
					t.Fatal("write outcome changed", report)
				}
				if mode == "same" {
					if report.attempt != a {
						t.Fatal("same-owner attempt lost")
					}
				} else if report.attempt != (transport.SendAttempt{}) {
					t.Fatal("unavailable attempt reassigned", mode)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("write report missing")
			}
			close(c.gone)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("write loop did not stop")
			}
		})
	}
}
