package node

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/types"
)

// A normal committed block with locally unavailable snapshot data checks
// validation origin without creating an invalid or forged network input.
func TestRoundProposalValidationOrigin(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	ev := &syncBuffer{}
	n := startNode(t, a, fsys.NewMem(), key, false, ev)
	a.waitHead(t, 3, 20*time.Second)
	stop(t, n)
	a.noSnapshot.Store(true)
	v := *n.view
	v.snaps = source.NewCache(4)
	var captured []event.Record
	v.emit = func(record event.Record) { captured = append(captured, record) }
	var err error
	v.rej, err = rejection.Open(fsys.NewMem(), "/local-rejections", rejection.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ValidateRoundProposal(a.block(2)); !errors.Is(err, header.ErrSnapshotMissing) {
		t.Fatal("local snapshot unavailability was not returned", err)
	}
	rows, err := v.rej.Range(types.HeightFromUint64(2).Big(), types.HeightFromUint64(2).Big())
	if err != nil || len(rows) != 1 || rows[0].Path != "local_reproposal" {
		t.Fatal("local candidate was recorded as a received proposal", rows, err)
	}
	if len(captured) != 1 || captured[0].Kind != event.Health || captured[0].Fields["what"] != "snapshot_missing_at_local_reproposal" {
		t.Fatal("local validation health origin lost", captured)
	}
}
