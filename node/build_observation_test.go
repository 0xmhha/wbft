package node

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

type heldBuildApp struct {
	*testApp
	requests []app.BuildRequest
}

func (a *heldBuildApp) ReadyToBuild(req app.BuildRequest) { a.requests = append(a.requests, req) }

func TestBuildHandoverIdentitySurvivesSameHeightAndDriverReplacement(t *testing.T) {
	cj, g := testGenesis(t, testKey(0))
	a := &heldBuildApp{testApp: newTestApp(cj, g)}
	var raw bytes.Buffer
	w := event.NewWriter(&raw, types.Address{1}, "observed-builds")
	at := event.Stamp{Wall: time.Unix(1700000000, 0), Mono: 0}
	emit := func(r event.Record) {
		at.Mono++
		if err := w.Write(r, at); err != nil {
			t.Fatal(err)
		}
	}
	var ids atomic.Uint64
	d := &appDriver{a: a, ctx: context.Background(), emit: emit, buildIDs: &ids}
	done := make(chan struct{})
	req := consensus.RequestBuild{Height: g.Header.Number.AddUint64(1), Round: types.RoundFromUint64(0)}
	d.ReadyToBuild(req, time.Second, done)
	d.ReadyToBuild(req, 0, done)
	a.requests[0].Observation.Finished(app.BuildReplaced, types.Hash{})
	a.requests[1].Observation.Started()
	hash := codec.BlockHash(g.Header)
	a.requests[1].Observation.Finished(app.BuildSubmitted, hash)
	// A new engine driver in the same node event run uses the shared ID counter.
	d = &appDriver{a: a, ctx: context.Background(), emit: emit, buildIDs: &ids}
	d.ReadyToBuild(req, 0, done)
	a.requests[2].Observation.Finished(app.BuildHeightLeft, types.Hash{})
	for _, r := range a.requests {
		if r.Height.Cmp(req.Height) != 0 || r.Round.Cmp(req.Round) != 0 || r.Parent != hash || r.Done != done {
			t.Fatal("dispatch changed application request", r)
		}
	}
	checkEvents(raw.Bytes())
	rows := map[string][]map[string]any{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw.Bytes()), []byte("\n")) {
		var r map[string]any
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		id := r["build_id"].(string)
		rows[id] = append(rows[id], r)
	}
	if len(rows) != 3 || len(rows["build-1"]) != 2 || len(rows["build-2"]) != 3 || len(rows["build-3"]) != 2 {
		t.Fatal("requests aliased or invented a start", rows)
	}
	if rows["build-2"][2]["hash"] != hash.Hex() || rows["build-2"][2]["status"] != "submitted" || rows["build-1"][1]["status"] != "replaced" {
		t.Fatal(rows)
	}
	if rows["build-1"][0]["wait_ns"] != "1000000000" {
		t.Fatal("wait precision lost", rows)
	}
}

func TestBuildHandoverWithoutObservationKeepsLegacyRequest(t *testing.T) {
	cj, g := testGenesis(t, testKey(0))
	a := &heldBuildApp{testApp: newTestApp(cj, g)}
	d := &appDriver{a: a}
	done := make(chan struct{})
	d.ReadyToBuild(consensus.RequestBuild{Height: g.Header.Number.AddUint64(1)}, 0, done)
	if len(a.requests) != 1 || a.requests[0].Observation != nil || a.requests[0].Done != done {
		t.Fatal("legacy dispatch changed", a.requests)
	}
}
