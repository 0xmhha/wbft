package sim

import (
	"context"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"testing"
)

func TestReceiveDispatchOriginalPreparationAndNormalCompletions(t *testing.T) {
	sc := writeQueueScenario(t, false)
	sc.Until.Height = 4
	for i := range sc.Nodes {
		sc.Nodes[i].AcceptedCache = cacheExperimentProfile()
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range s.nodes {
		n.stop()
	}
	if result := s.result(); len(result.Violations) > 0 {
		t.Fatal(result.Violations)
	}
	for _, n := range s.nodes {
		records, err := journal.ReadAll(n.fs, journalDir)
		if err != nil {
			t.Fatal(err)
		}
		check, err := journal.CheckReceiveDispatchSources(records, journal.ReceiveDispatchLimits{Receive: cacheSourceLimits(), Selections: selectionSourceBounds(), Operations: 20000, Bytes: 64 << 20})
		if err != nil || check.Status != "consistent" || check.Dispatched == 0 || check.DiscardedKnown != 0 || check.SelfRegistrations == 0 || check.RetainedPreparations != 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
			t.Fatal("independent normal receive disposition", n.i, check, err)
		}
		core, err := journal.CheckCoreStepSources(records, cacheSourceLimits().Core)
		if err != nil || core.Status != "consistent" {
			t.Fatal("normal independent core control failed", core, err)
		}
		type key struct {
			run              string
			ledger, sequence uint64
		}
		transitions := map[key]transport.ReceiveTransition{}
		writer := ""
		for _, record := range records {
			switch r := record.Body.(type) {
			case *journal.SegmentRec:
				writer = r.Run
			case *journal.ReceiveCacheRec:
				transitions[key{writer, r.Transition.Ledger, r.Transition.Sequence}] = r.Transition
			}
		}
		prepared := map[uint64]*journal.ReceiveDispatchRec{}
		var previous, completed uint64
		for _, record := range records {
			r, ok := record.Body.(*journal.ReceiveDispatchRec)
			if !ok {
				continue
			}
			if r.Sequence != previous+1 || r.Unavailable != "" {
				t.Fatal("normal original reference unavailable", n.i, r)
			}
			previous = r.Sequence
			if r.Action == "prepare" {
				transition, found := transitions[key{r.Source.WriterRun, r.Source.Ledger, r.Source.Sequence}]
				if !found || transition.Action != transport.ReceiveCheckPrepare || uint64(transition.Decision) != r.Decision || transition.Scope != r.Scope {
					t.Fatal("prepare referred to another actual ledger call", r, transition)
				}
				decoded, err := inputlog.Decode(r.InputKind, r.Input, nil)
				if err != nil {
					t.Fatal(err)
				}
				m, ok := decoded.(consensus.Message)
				if !ok || uint64(m.Code) != transition.Input.Code || m.Peer != transition.Input.Peer || r.Origin != transition.Origin || r.StreamRun != transition.Input.SessionRun || r.Stream != transition.Input.Session {
					t.Fatal("original input identity changed", r, transition)
				}
				prepared[r.Request] = r
			} else {
				p := prepared[r.Request]
				if p == nil || r.Source != p.Source || r.Selection != p.Selection || r.InboxRequest != p.InboxRequest || r.InternalRequest != p.InternalRequest || r.ContextHash != p.ContextHash || r.BeforeStep != p.BeforeStep || r.Scope != p.Scope {
					t.Fatal("completion lost original preparation owner", r, p)
				}
				if r.Action != "dispatch" || r.Step != r.BeforeStep+1 {
					t.Fatal("ordinary source unexpectedly claimed a known discard", r)
				}
				delete(prepared, r.Request)
				completed++
			}
		}
		if completed == 0 || len(prepared) != 0 {
			t.Fatal("normal preparation/completion boundary missing", n.i, completed, len(prepared))
		}
	}
}
