package journal

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// FinalizeLimits bound retained diagnostic indexes and encoded spans. They do
// not bound live application execution, process heap or decoding allocations.
type FinalizeLimits struct {
	Queue                    AppQueueLimits
	Operations, Tasks, Bytes uint64
}

type FinalizeCheck struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Scope            string `json:"scope"`
	PhysicalStatus   string `json:"physical_status"`
	ScheduleStatus   string `json:"schedule_status"`
	Enqueued         uint64 `json:"enqueued,string"`
	Entered          uint64 `json:"entered,string"`
	Returned         uint64 `json:"returned,string"`
	Notified         uint64 `json:"notified,string"`
	RetainedQueued   uint64 `json:"retained_queued,string"`
	RetainedActive   uint64 `json:"retained_active,string"`
	RetainedReturned uint64 `json:"retained_returned,string"`
}

var ErrFinalizeSource = errors.New("journal: inconsistent application finalization source")

type finalizeOutputKey struct {
	appCoreKey
	output uint64
}
type finalizeQueueKey struct {
	writer  string
	request uint64
}
type finalizeExpected struct {
	arguments      []byte
	hash           types.Hash
	view           types.View
	bound          bool
	mono, observed time.Duration
	seen           bool
}
type finalizePending struct {
	source   *FinalizeRec
	expected *finalizeExpected
	phase    string
	hasError bool
}

// CheckFinalizeSources binds independently recomputed Commit outputs to actual
// commit-queue mutations, call/return boundaries and original AppQueue append
// coordinates. It checks diagnostic consistency, not application state execution
// or a closed runtime schedule. A finite horizon may retain unfinished tasks.
func CheckFinalizeSources(records []Record, limits FinalizeLimits) (FinalizeCheck, error) {
	return checkFinalizeSources(records, limits, false)
}

func checkFinalizeSources(records []Record, limits FinalizeLimits, restored bool) (FinalizeCheck, error) {
	report := FinalizeCheck{Status: "unavailable", Scope: "commit_queue_application_call_and_result_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (FinalizeCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (FinalizeCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrFinalizeSource, reason)
	}
	if limits.Operations == 0 || limits.Tasks == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	queue, err := checkAppQueueSources(records, limits.Queue, restored)
	if err != nil {
		return inconsistent("queue_" + queue.Reason)
	}
	if queue.Status != "consistent" {
		return unavailable("queue_" + queue.Reason)
	}
	profiles := map[string]consensus.ImprovementSet{}
	for _, r := range records {
		if s, ok := r.Body.(*SegmentRec); ok {
			profiles[s.Run] = consensus.ImprovementSet(s.Core.Improvements)
		}
	}
	outputs := map[finalizeOutputKey]*finalizeExpected{}
	var span uint64
	issue := ""
	core, _, err := inspectApplicationCoreOutputs(records, limits.Queue.Core, restored, func(writer string, source *CoreStepRec, outs []consensus.Output) {
		if issue != "" {
			return
		}
		for i, out := range outs {
			c, ok := out.(consensus.Commit)
			if !ok {
				continue
			}
			if uint64(len(outputs)) >= limits.Tasks {
				issue = "finalization_task_limit"
				return
			}
			args, e := inputlog.EncodeOutputs([]consensus.Output{c})
			if e != nil {
				issue = "commit_output_encoding"
				return
			}
			if uint64(len(args)) > limits.Bytes-span {
				issue = "finalization_byte_limit"
				return
			}
			span += uint64(len(args))
			p := profiles[writer]
			outputs[finalizeOutputKey{appCoreKey{writer, source.EngineRun, source.Step}, uint64(i + 1)}] = &finalizeExpected{arguments: args, hash: codec.BlockHash(c.Block.Header), view: types.View{Sequence: c.Block.Header.Number, Round: c.Round}, bound: p.Has(consensus.WatchCommittedImport) || p.Has(consensus.AdvanceOnCommitFailure), mono: time.Duration(source.Entry.Mono), observed: time.Duration(source.Observed.Mono)}
		}
	})
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	if issue != "" {
		return unavailable(issue)
	}
	groups := map[string][]*FinalizeRec{}
	appends := map[finalizeQueueKey]*AppQueueRec{}
	linked := map[finalizeQueueKey]bool{}
	writer := ""
	var operations uint64
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindFinalize)) {
					return unavailable("finalization_source_gap")
				}
			}
		case *AppQueueRec:
			if r.Action == "append" && r.InputKind == inputlog.KindCommitResult {
				appends[finalizeQueueKey{writer, r.Request}] = r
			}
		case *FinalizeRec:
			if operations >= limits.Operations {
				return unavailable("finalization_operation_limit")
			}
			operations++
			if r.Version != FinalizeSourceVersion {
				return unavailable("finalization_version")
			}
			if !validFinalizeRec(r) {
				return inconsistent("invalid_finalization_source")
			}
			if r.Unavailable != "" {
				return unavailable("finalization_" + r.Unavailable)
			}
			if writer == "" {
				return unavailable("finalization_writer_missing")
			}
			n := uint64(len(r.Arguments)) + uint64(len(r.Input)) + uint64(len(r.QueueRun))
			if n > limits.Bytes-span {
				return unavailable("finalization_byte_limit")
			}
			span += n
			groups[writer] = append(groups[writer], r)
		}
	}
	if operations == 0 {
		return unavailable("no_finalization_sources")
	}
	writers := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before validation
		writers = append(writers, name)
	}
	slices.Sort(writers)
	for _, name := range writers {
		items := groups[name]
		slices.SortFunc(items, func(a, b *FinalizeRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		pending := map[uint64]*finalizePending{}
		var fifo []uint64
		var sequence uint64
		var mono time.Duration
		var active uint64
		for _, r := range items {
			if r.Sequence == sequence {
				return inconsistent("finalization_sequence_repeated")
			}
			if r.Sequence != sequence+1 {
				return unavailable("finalization_sequence_gap")
			}
			if r.Mono < mono {
				return inconsistent("finalization_clock_changed")
			}
			sequence, mono = r.Sequence, r.Mono
			key := finalizeOutputKey{appCoreKey{name, r.EngineRun, r.Step}, r.Output}
			p := pending[r.Task]
			if r.Action == "enqueue" {
				expected := outputs[key]
				if expected == nil {
					return unavailable("finalization_core_output_missing")
				}
				if expected.seen || p != nil || !bytes.Equal(expected.arguments, r.Arguments) || (r.Mono < expected.mono || r.Mono > expected.observed) {
					return inconsistent("finalization_commit_owner_changed")
				}
				if r.Before != uint64(len(fifo)) || r.After != r.Before+1 {
					return inconsistent("finalization_queue_count_changed")
				}
				expected.seen = true
				pending[r.Task] = &finalizePending{source: r, expected: expected, phase: "queued"}
				fifo = append(fifo, r.Task)
				report.Enqueued++
				continue
			}
			if p == nil {
				return unavailable("finalization_enqueue_missing")
			}
			if p.source.EngineRun != r.EngineRun || p.source.Step != r.Step || p.source.Output != r.Output {
				return inconsistent("finalization_task_owner_changed")
			}
			switch r.Action {
			case "dequeue":
				if len(fifo) == 0 || fifo[0] != r.Task || p.phase != "queued" || active != 0 {
					return inconsistent("finalization_fifo_changed")
				}
				if r.Before != uint64(len(fifo)) || r.After+1 != r.Before {
					return inconsistent("finalization_queue_count_changed")
				}
				fifo = fifo[1:]
				active = r.Task
				p.phase = "dequeued"
			case "enter":
				if active != r.Task || p.phase != "dequeued" || !bytes.Equal(p.expected.arguments, r.Arguments) {
					return inconsistent("finalization_call_changed")
				}
				p.phase = "active"
				report.Entered++
			case "return":
				if active != r.Task || p.phase != "active" {
					return inconsistent("finalization_return_changed")
				}
				p.phase, p.hasError = "returned", r.HasError
				report.Returned++
			case "notify":
				if active != r.Task || p.phase != "returned" || p.hasError != r.HasError {
					return inconsistent("finalization_notification_changed")
				}
				qkey := finalizeQueueKey{r.QueueRun, r.QueueRequest}
				q := appends[qkey]
				if q == nil {
					return unavailable("finalization_queue_append_missing")
				}
				if r.QueueRun != name || linked[qkey] || !bytes.Equal(q.Input, r.Input) || q.Mono > r.Mono {
					return inconsistent("finalization_queue_append_changed")
				}
				decoded, e := inputlog.Decode(inputlog.KindCommitResult, r.Input, nil)
				if e != nil {
					return inconsistent("finalization_result_encoding")
				}
				result, ok := decoded.(consensus.CommitResult)
				if !ok || result.Hash != p.expected.hash {
					return inconsistent("finalization_result_changed")
				}
				if (result.Err != nil) != r.HasError {
					return unavailable("finalization_error_presence_unrepresentable")
				}
				if p.expected.bound != (result.View != nil) {
					return inconsistent("finalization_result_view_changed")
				}
				if result.View != nil && (result.View.Sequence.Cmp(p.expected.view.Sequence) != 0 || result.View.Round.Cmp(p.expected.view.Round) != 0) {
					return inconsistent("finalization_result_view_changed")
				}
				linked[qkey] = true
				delete(pending, r.Task)
				active = 0
				report.Notified++
			}
		}
		report.RetainedQueued += uint64(len(fifo))
		if active != 0 {
			if pending[active].phase == "returned" {
				report.RetainedReturned++
			} else {
				report.RetainedActive++
			}
		}
	}
	for _, p := range outputs { //wbft:unordered identical missing-source result
		if !p.seen {
			return unavailable("finalization_core_commit_unobserved")
		}
	}
	for key := range appends { //wbft:unordered identical missing-source result
		if !linked[key] {
			return unavailable("finalization_result_unobserved")
		}
	}
	report.Status = "consistent"
	return report, nil
}
