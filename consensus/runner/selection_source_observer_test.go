package runner

import (
	"bytes"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
)

type selectionObservations struct {
	records []journal.SelectionRec
	inspect func()
}

func (o *selectionObservations) ObserveInputSelection(r journal.SelectionRec) {
	if o.inspect != nil {
		o.inspect()
	}
	copy := r
	copy.Input = bytes.Clone(r.Input)
	o.records = append(o.records, copy)
	if len(r.Input) > 0 {
		r.Input[0] ^= 1
	}
}

func TestSelectionObserverPreservesNormalInputsDrawsAndUnlockedCallbacks(t *testing.T) {
	k := newKeys(t, 4)
	type result struct {
		draws           int
		prepare, commit [][]byte
		state           consensus.StateName
	}
	results := []result{}
	for _, observe := range []bool{false, true} {
		n := newTNode(t, k, 1)
		n.noJournal = true
		n.boot()
		draws := 0
		original := n.r.d.Rand
		n.r.d.Rand = func(bound int) int { draws++; return original(bound) }
		o := new(selectionObservations)
		if observe {
			o.inspect = func() {
				if !n.r.appMu.TryLock() {
					t.Fatal("selection observer holds app mutex")
				}
				n.r.appMu.Unlock()
				if !n.r.timers.mu.TryLock() {
					t.Fatal("selection observer holds timer mutex")
				}
				n.r.timers.mu.Unlock()
				if !n.r.inbox.mu.TryLock() {
					t.Fatal("selection observer holds inbox mutex")
				}
				n.r.inbox.mu.Unlock()
			}
			n.r.d.SelectionSources = o
		}
		b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
		n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
		for _, peer := range []int{0, 2} {
			n.deliver(peer, codec.CodePrepare, k.vote(t, peer, codec.CodePrepare, view(10, 0), b))
		}
		state := n.r.Vars().State
		if state != consensus.Prepared || n.r.d.Journal != nil {
			t.Fatal("observer changed normal state or enabled recording")
		}
		results = append(results, result{draws, n.net.own(codec.CodePrepare), n.net.own(codec.CodeCommit), state})
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		if observe {
			selected, dispatched := 0, 0
			for i, r := range o.records {
				if r.Sequence != uint64(i+1) {
					t.Fatal("original selection sequence lost", r)
				}
				switch r.Action {
				case "select":
					// Partial diagnostic hooks must not claim a fully reconstructable lane.
					if r.Unavailable != "lane_source_missing" {
						t.Fatal("missing original lane sources accepted", r)
					}
					if r.Lane != "none" {
						selected++
					}
					if r.Lane == "internal" && (r.App.State != "not_probed" || r.Timer.State != "not_probed" || r.Inbox.State != "not_probed") {
						t.Fatal("later probes invented", r)
					}
				case "dispatch":
					dispatched++
				}
			}
			if selected == 0 || selected != dispatched {
				t.Fatal("selection was not bound to actual dispatch", selected, dispatched)
			}
		}
	}
	if results[0].draws == 0 || results[0].draws != results[1].draws || results[0].state != results[1].state || !slices.EqualFunc(results[0].prepare, results[1].prepare, bytes.Equal) || !slices.EqualFunc(results[0].commit, results[1].commit, bytes.Equal) {
		t.Fatal("observer changed actual signed output or random calls", results)
	}
}
