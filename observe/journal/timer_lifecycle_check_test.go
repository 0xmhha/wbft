package journal

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

func lifecycleBounds() TimerSourceLimits {
	return TimerSourceLimits{Core: CoreSourceLimits{Records: 100, Runs: 4, Steps: 20, Environments: 20, Outputs: 100, Bytes: 1 << 20}, Operations: 100, Bindings: 100, Bytes: 1 << 20}
}

// These are detached metadata examples, never inputs to a live timer or core.
func lifecycleFixture(t *testing.T, kind consensus.TimerKind) []Record {
	t.Helper()
	payload := func(gen uint64) []byte {
		raw, err := inputlog.Encode(consensus.Timeout{Kind: kind, Gen: gen, View: types.View{Sequence: types.HeightFromUint64(2)}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	arm := func(seq, step uint64, entry, deadline time.Duration, gen uint64) *TimerRec {
		return &TimerRec{Sequence: seq, EngineRun: 1, Step: step, Output: 1, ArmEngineRun: 1, ArmStep: step, ArmOutput: 1, Source: "core", Action: "arm", Mono: entry, EntryMono: entry, Deadline: deadline, Input: payload(gen)}
	}
	first := arm(1, 1, 0, 10, 1)
	queued := *first
	queued.Sequence, queued.Action, queued.Mono = 2, "queued", 10
	pop := queued
	pop.Sequence, pop.Step, pop.Output, pop.Source, pop.Action = 3, 2, 0, "dequeue", "pop"
	second := arm(4, 3, 12, 22, 2)
	replaced := *second
	replaced.Sequence, replaced.Step, replaced.Mono, replaced.Action = 5, 4, 14, "replace"
	third := arm(6, 4, 14, 24, 3)
	cancelled := *third
	cancelled.Sequence, cancelled.Step, cancelled.Mono, cancelled.Action = 7, 5, 16, "cancelled"
	items := []*TimerRec{first, &queued, &pop, second, &replaced, third, &cancelled,
		{Sequence: 8, EngineRun: 1, Step: 5, Output: 1, Source: "core", Action: "cancel", Mono: 16, Kinds: []uint64{uint64(kind)}},
		{Sequence: 9, EngineRun: 1, Step: 6, Source: "lifecycle", Action: "cancel", Mono: 30, Kinds: []uint64{0, 1, 2, 3}},
		{Sequence: 10, EngineRun: 1, Step: 6, Source: "lifecycle", Action: "clear", Mono: 30}}
	records := []Record{{Body: &SegmentRec{Identity: Identity{Run: "writer", Core: CoreOptions{TimerTrace: TimerTraceVersion}}}}}
	for _, s := range []struct {
		step            uint64
		entry, observed int64
		kind            string
	}{
		{1, 0, 1, inputlog.KindStart}, {2, 11, 12, inputlog.KindTimeout}, {3, 12, 13, inputlog.KindMessage},
		{4, 14, 15, inputlog.KindMessage}, {5, 16, 17, inputlog.KindMessage}, {6, 29, 30, inputlog.KindStop},
	} {
		records = append(records, Record{Body: &CoreStepRec{EngineRun: 1, Step: s.step, InputKind: s.kind, Input: payload(1), Entry: CoreStepMoment{Mono: s.entry}, Observed: CoreStepMoment{Mono: s.observed}}})
	}
	for _, item := range items {
		records = append(records, Record{Body: item})
	}
	return records
}

func TestTimerLifecycleDetachedMetadataAllKinds(t *testing.T) {
	for _, kind := range consensus.SupportedTimers {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			records := lifecycleFixture(t, kind)
			report, err := inspectTimerLifecycle(records, lifecycleBounds())
			if err != nil || report.Status != "consistent" || report.Arms != 3 || report.Replacements != 1 || report.Cancellations != 1 || report.Queued != 1 || report.Popped != 1 || report.Clears != 1 || report.RetainedLive != 0 || report.RetainedQueued != 0 || report.ScheduleStatus != "unavailable" || report.PhysicalStatus != "unavailable" {
				t.Fatal(report, err)
			}
			// Detached callbacks can arrive in reverse order; the original
			// mutex sequence still describes the same finite state history.
			slices.Reverse(records[7:])
			reordered, err := inspectTimerLifecycle(records, lifecycleBounds())
			if err != nil || reordered != report {
				t.Fatal("observer delivery order changed source validation", reordered, err)
			}
		})
	}
}

func TestTimerLifecycleOfflineContradictions(t *testing.T) {
	for _, mode := range []string{"old_arm", "early_queue", "wrong_timeout", "wrong_cause", "wrong_stop", "repeated_sequence", "backwards_clock", "duplicate_pop"} {
		t.Run(mode, func(t *testing.T) {
			records := lifecycleFixture(t, consensus.RoundTimer)
			for i, record := range records {
				r, ok := record.Body.(*TimerRec)
				if !ok {
					continue
				}
				value := *r
				change := false
				switch {
				case mode == "old_arm" && r.Sequence == 5:
					value.ArmStep, change = 1, true
				case mode == "early_queue" && r.Sequence == 2:
					value.Mono, change = 9, true
				case mode == "wrong_timeout" && r.Sequence == 3:
					value.Input, change = []byte{0xc0}, true
				case mode == "wrong_cause" && r.Sequence == 7:
					value.Output, change = 2, true
				case mode == "wrong_stop" && r.Sequence == 10:
					value.Step, change = 5, true
				case mode == "repeated_sequence" && r.Sequence == 3:
					value.Sequence, change = 2, true
				case mode == "backwards_clock" && r.Sequence == 3:
					value.Mono, change = 9, true
				case mode == "duplicate_pop" && r.Sequence == 4:
					value = *records[9].Body.(*TimerRec)
					value.Sequence, value.Mono, change = 4, 12, true
				}
				if change {
					records[i].Body = &value
					break
				}
			}
			report, err := inspectTimerLifecycle(records, lifecycleBounds())
			if report.Status != "inconsistent" || !errors.Is(err, ErrTimerLifecycleSource) {
				t.Fatal("offline contradiction accepted", report, err)
			}
		})
	}
}

func TestTimerLifecycleIncompleteMetadataUnavailable(t *testing.T) {
	for _, mode := range []string{"sequence_gap", "restoration", "operation_limit", "byte_limit", "missing_step"} {
		t.Run(mode, func(t *testing.T) {
			records := lifecycleFixture(t, consensus.RoundTimer)
			limits := lifecycleBounds()
			switch mode {
			case "sequence_gap":
				records = append(records[:8:8], records[9:]...)
			case "restoration":
				value := *records[7].Body.(*TimerRec)
				value.Source = "restore"
				records[7].Body = &value
			case "operation_limit":
				limits.Operations = 1
			case "byte_limit":
				limits.Bytes = 1
			case "missing_step":
				records = append(records[:1:1], records[2:]...)
			}
			report, err := inspectTimerLifecycle(records, limits)
			if err != nil || report.Status != "unavailable" {
				t.Fatal("missing evidence became proof", report, err)
			}
		})
	}
}

func TestTimerLifecyclePublicCheckRequiresCoreSources(t *testing.T) {
	report, err := CheckTimerLifecycleSources(lifecycleFixture(t, consensus.RoundTimer), lifecycleBounds())
	if report.Status == "consistent" || report.ScheduleStatus != "unavailable" || report.PhysicalStatus != "unavailable" {
		t.Fatal("unverified metadata became core execution proof", report, err)
	}
}

func TestTimerLifecycleQueuedExpirySurvivesCancellation(t *testing.T) {
	records := lifecycleFixture(t, consensus.RoundTimer)
	for i, record := range records[:7] {
		if step, ok := record.Body.(*CoreStepRec); ok {
			value := *step
			if step.Step == 2 {
				value.InputKind, value.Entry.Mono, value.Observed.Mono = inputlog.KindMessage, 10, 10
			}
			if step.Step == 3 {
				value.InputKind, value.Entry.Mono, value.Observed.Mono = inputlog.KindTimeout, 11, 12
			}
			records[i].Body = &value
		}
	}
	pop := *records[9].Body.(*TimerRec)
	pop.Sequence, pop.Step, pop.Mono = 4, 3, 11
	stop := *records[15].Body.(*TimerRec)
	stop.Sequence = 5
	clear := *records[16].Body.(*TimerRec)
	clear.Sequence = 6
	retained := append(slices.Clone(records[:9]), Record{Body: &TimerRec{Sequence: 3, EngineRun: 1, Step: 2, Output: 1, Source: "core", Action: "cancel", Mono: 10, Kinds: []uint64{0}}}, Record{Body: &pop}, Record{Body: &stop}, Record{Body: &clear})
	report, err := inspectTimerLifecycle(retained, lifecycleBounds())
	if err != nil || report.Status != "consistent" || report.Queued != 1 || report.Popped != 1 || report.RetainedQueued != 0 {
		t.Fatal("cancel discarded an already queued expiry", report, err)
	}
}

func TestTimerLifecycleEqualDeadlineQueueOrder(t *testing.T) {
	records := lifecycleFixture(t, consensus.RoundTimer)
	first := *records[7].Body.(*TimerRec)
	second := first
	second.Sequence, second.Step, second.ArmStep, second.Mono, second.EntryMono = 2, 3, 3, 2, 2
	var err error
	second.Input, err = inputlog.Encode(consensus.Timeout{Kind: consensus.RetryTimer, Gen: 1, View: types.View{Sequence: types.HeightFromUint64(2)}})
	if err != nil {
		t.Fatal(err)
	}
	for i, record := range records[:7] {
		if step, ok := record.Body.(*CoreStepRec); ok {
			value := *step
			if step.Step == 3 {
				value.Entry.Mono, value.Observed.Mono = 2, 3
			}
			if step.Step == 4 {
				value.InputKind, value.Input, value.Entry.Mono, value.Observed.Mono = inputlog.KindTimeout, second.Input, 13, 14
			}
			records[i].Body = &value
		}
	}
	queuedFirst, queuedSecond := first, second
	queuedFirst.Sequence, queuedFirst.Action, queuedFirst.Mono = 3, "queued", 10
	queuedSecond.Sequence, queuedSecond.Action, queuedSecond.Mono = 4, "queued", 10
	popFirst, popSecond := queuedFirst, queuedSecond
	popFirst.Sequence, popFirst.Step, popFirst.Output, popFirst.Action, popFirst.Source, popFirst.Mono = 5, 2, 0, "pop", "dequeue", 11
	popSecond.Sequence, popSecond.Step, popSecond.Output, popSecond.Action, popSecond.Source, popSecond.Mono = 6, 4, 0, "pop", "dequeue", 13
	retained := slices.Clone(records[:7])
	for _, r := range []*TimerRec{&first, &second, &queuedFirst, &queuedSecond, &popFirst, &popSecond} {
		retained = append(retained, Record{Body: r})
	}
	report, err := inspectTimerLifecycle(retained, lifecycleBounds())
	if err != nil || report.Status != "consistent" || report.Popped != 2 {
		t.Fatal(report, err)
	}
	changedFirst, changedSecond := popSecond, popFirst
	changedFirst.Sequence, changedFirst.Mono = 5, 11
	changedSecond.Sequence, changedSecond.Mono = 6, 13
	retained[11].Body, retained[12].Body = &changedFirst, &changedSecond
	report, err = inspectTimerLifecycle(retained, lifecycleBounds())
	if report.Status != "inconsistent" || report.Reason != "timer_dequeue_order_changed" || !errors.Is(err, ErrTimerLifecycleSource) {
		t.Fatal("equal deadlines replaced original queue order", report, err)
	}
}
