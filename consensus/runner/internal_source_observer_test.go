package runner

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

type internalObservations struct {
	records []journal.InternalRec
	alter   bool
	writer  journal.Writer
}

func (o *internalObservations) ObserveInternalSource(r journal.InternalRec) {
	detached := r
	detached.Input = bytes.Clone(r.Input)
	o.records = append(o.records, detached)
	if o.writer != nil {
		o.writer.Put(journal.Record{Body: &detached})
	}
	if o.alter && len(r.Input) > 0 {
		r.Input[0] ^= 1
	}
}

func TestInternalSourcesDetachedNormalSigningAndRestoredPrefix(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	o := &internalObservations{alter: true}
	n.internalSources = o
	n.boot()
	t.Cleanup(func() {
		if err := n.r.Close(); err != nil {
			t.Error(err)
		}
		if err := n.log.Close(); err != nil {
			t.Error(err)
		}
	})
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
	for _, peer := range []int{0, 2} {
		n.deliver(peer, codec.CodePrepare, k.vote(t, peer, codec.CodePrepare, view(10, 0), b))
	}
	if n.r.Vars().State != consensus.Prepared || len(n.net.own(codec.CodeCommit)) != 1 || n.r.d.Journal != nil {
		t.Fatal("detached observer changed normal signing or enabled functional journal")
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	appends := map[uint64]journal.InternalRec{}
	popped := map[uint64]bool{}
	var resets, clears, dispatches, restored int
	for i, r := range o.records {
		if r.Sequence != uint64(i+1) {
			t.Fatal("original loop sequence lost", r)
		}
		if r.Origin == "replay" {
			if r.EngineRun != 2 || r.Action != "append" || r.Step != 0 || r.Output != 0 || r.Unavailable != "replay_prefix" {
				t.Fatal("restored prefix acquired live owner", r)
			}
			restored++
			continue
		}
		if r.Unavailable != "" {
			t.Fatal("original loop sequence or availability lost", r)
		}
		switch r.Action {
		case "reset":
			resets++
		case "clear":
			clears++
		case "append":
			if r.Step == 0 || r.Output == 0 || r.Request != r.Sequence {
				t.Fatal("original output owner lost", r)
			}
			if _, err := inputlog.Decode(r.InputKind, r.Input, nil); err != nil {
				t.Fatal("observer changed retained bytes", err)
			}
			appends[r.Request] = r
		case "pop":
			a, ok := appends[r.Request]
			if !ok || !bytes.Equal(a.Input, r.Input) || popped[r.Request] {
				t.Fatal("take lost source", r)
			}
			popped[r.Request] = true
		case "dispatch":
			if !popped[r.Request] || r.Step == 0 || !bytes.Equal(appends[r.Request].Input, r.Input) {
				t.Fatal("dispatch invented source", r)
			}
			dispatches++
		}
	}
	if len(appends) < 2 || len(popped) != len(appends) || dispatches != len(popped) || resets != 2 || clears != 2 || restored == 0 {
		t.Fatal("normal execution boundaries missing", len(appends), len(popped), dispatches, resets, clears)
	}
}

func TestInternalSourcesExhaustedMetadataNeverReassigns(t *testing.T) {
	r := &Runner{engineRun: 1, step: 2, d: Deps{Clock: &manualClock{}, InternalSources: new(internalObservations)}}
	r.internalSourceSequence = ^uint64(0)
	first := r.internalRecord("append", queued{}, "schedule", 1, 0)
	r.internalSourceSequence = 1
	second := r.internalRecord("append", queued{}, "schedule", 1, 0)
	if first.Sequence != 0 || first.Request != 0 || first.Unavailable != "metadata_exhausted" || second.Sequence != 0 || second.Request != 0 || second.Unavailable != "metadata_exhausted" {
		t.Fatal("exhausted metadata rebound", first, second)
	}
}

func TestInternalSourcesNormalEarlyVoteSchedulesExactBacklog(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/internal-source", Synchronous: true}, journal.Identity{Run: "internal-source", Self: n.opts.Self, Mode: "diagnostic", Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit)}})
	if err != nil {
		t.Fatal(err)
	}
	n.coreSteps = &coreObservations{writer: w}
	n.internalSources = &internalObservations{writer: w}
	n.boot()
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	// A genuine signed vote can arrive before its genuine proposal. No clock,
	// payload, signature, admission rule or functional fault point is altered.
	n.deliver(2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), b))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
	n.deliver(0, codec.CodePrepare, k.vote(t, 0, codec.CodePrepare, view(10, 0), b))
	if n.r.Vars().State != consensus.Prepared {
		t.Fatal("ordinary backlog did not prepare")
	}
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/internal-source")
	if err != nil {
		t.Fatal(err)
	}
	limits := journal.InternalLimits{Core: journal.CoreSourceLimits{Records: 1000, Runs: 4, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20}, Operations: 100, Entries: 16, Outputs: 100, Bytes: 1 << 20}
	check, err := journal.CheckInternalSources(records, limits)
	if err != nil || check.Status != "consistent" || check.Scheduled != 1 || check.OwnMessages != 2 || check.Appended != 3 || check.Popped != 3 || check.Dispatched != 3 || check.Clears != 1 {
		t.Fatal("independent Schedule/input binding missing", check, err)
	}
}
