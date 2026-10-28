package runner

import (
	"context"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// This is a local receiver API authority mismatch with intact signatures made
// by owned keys. It transmits no network frames and alters no signature bytes.
func TestReceiveFailureCacheActualMembershipWorkerAndNormalRestart(t *testing.T) {
	members, owned := newKeys(t, 4), newKeys(t, 5)
	var baseline *consensus.Vars
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, members, 1)
		n.noJournal = true
		n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
		if enabled {
			n.receiveFailureCache = &transport.ReceiveFailureOptions{Entries: 2}
		}
		var checks []consensus.RecoveryFailure
		hits := 0
		n.receiveRecoveryChecked = func(_ codec.Code, phase consensus.RecoveryFailure) { checks = append(checks, phase) }
		n.receiveFailureHit = func(_ uint64, class transport.ReceiveFailureClass) {
			if class != transport.ReceiveMembershipFailure {
				t.Error("membership hit changed its classified phase")
			}
			hits++
		}
		n.boot()
		t.Cleanup(func() {
			if err := n.r.Close(); err != nil {
				t.Error(err)
			}
			if err := n.log.Close(); err != nil {
				t.Error(err)
			}
		})
		b := block(t, 10, 1, members.addrs[0], codec.BlockHash(n.chain.head))
		raw := owned.vote(t, 4, codec.CodePrepare, view(10, 0), b)
		// Verify cryptographic validity independently of the receiver's four-member context.
		if v, err := consensus.Recover(codec.CodePrepare, raw, nil); err != nil || v.Source != owned.addrs[4] {
			t.Fatal("owned intact fixture was not validly signed", err)
		}
		in := transportInbound(members, 0, codec.CodePrepare, raw, n.clock.now)
		feed := func() {
			t.Helper()
			if !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) {
				t.Fatal("ordinary local authority check was not consumed")
			}
		}
		step := n.r.step
		publication := n.r.snap.loadPublication()
		feed()
		if len(checks) != 1 || checks[0] != consensus.RecoveryMembership || hits != 0 {
			t.Fatal("first actual worker verification did not report its real failure")
		}
		if enabled && n.r.receiveFailures.Len() != 1 {
			t.Fatal("actual membership failure was not retained")
		}
		feed()
		want := 2
		if enabled {
			want = 1
		}
		if len(checks) != want || hits != 2-want || n.r.step != step {
			t.Fatal("hit was counted as actual recovery or advanced the core", len(checks), hits)
		}
		current := n.r.receiveContext.Load()
		if current != nil && (n.r.receiveCache.Known(current.scope, in.Code, raw) || n.r.receiveCache.Recent(current.scope, in.Peer, in.Code, raw)) {
			t.Fatal("failed input became accepted authority")
		}
		n.deliver(0, codec.CodePreprepare, members.preprepare(t, 0, view(10, 0), b))
		n.deliver(0, codec.CodePrepare, members.vote(t, 0, codec.CodePrepare, view(10, 0), b))
		if enabled && (n.r.currentFailureContext(publication) != nil || n.r.receiveFailures.Len() != 0) {
			t.Fatal("normal core publication retained a prior failure context")
		}
		before := len(checks)
		feed()
		if len(checks) != before+1 || checks[len(checks)-1] != consensus.RecoveryMembership {
			t.Fatal("new publication reused an old failure instead of actual recovery")
		}
		if enabled && hits != 1 {
			t.Fatal("new publication produced a false hit")
		}
		vars := n.r.Vars()
		if !enabled {
			baseline = vars
		} else if !reflect.DeepEqual(vars, baseline) {
			t.Fatal("failure caching changed normal consensus state")
		}
		old := n.r.snap.loadPublication()
		if err := n.r.Stop(); err != nil {
			t.Fatal(err)
		}
		if enabled && (n.r.receiveFailures.Len() != 0 || n.r.currentFailureContext(old) != nil) {
			t.Fatal("normal Stop retained failure ownership")
		}
		if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
			t.Fatal(err)
		}
		n.r.Pump()
		before = len(checks)
		feed()
		if len(checks) != before+1 {
			t.Fatal("normal engine restart reused a prior generation's failure")
		}
		if enabled && n.r.receiveFailures.Len() != 1 {
			t.Fatal("restarted engine did not use its new failure lifetime")
		}
		t.Logf("receive_failure_worker enabled=%t initial_actual_checks=%d initial_hits=%d cryptographic_failure_hit_observed=false diagnostic_profile_supported=false", enabled, want, 2-want)
	}
}
