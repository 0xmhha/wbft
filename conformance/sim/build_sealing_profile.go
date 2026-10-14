package sim

import (
	"fmt"
	"time"
)

func durationTexts(samples []time.Duration) []string {
	if len(samples) == 0 {
		return []string{"0"}
	}
	out := make([]string, len(samples))
	for i, d := range samples {
		out[i] = fmt.Sprint(int64(d))
	}
	return out
}
func (b *sealingBuilder) declaration() map[string]any {
	builds, imports := b.a.n.spec.BuildDelay, b.a.n.spec.ImportDelay
	if len(builds) == 0 {
		builds = b.a.n.s.sc.App.BuildDelay
	}
	if len(imports) == 0 {
		imports = b.a.n.s.sc.App.ImportDelay
	}
	return map[string]any{"build_queue": BuildQueueSealing, "assembly_return": "sampled_empty_body", "running_gate": "at_selection", "selection": "actors_to_idle_then_deadline_callbacks_seeded", "commit_capacity": 1, "result_capacity": b.a.n.spec.Sealing.ResultCapacity, "head_capacity": sealingHeadCapacity, "pending_age": sealingPendingAge, "call_return_delay_ns": durationTexts(b.a.n.spec.Sealing.CallDelay), "post_delay_ns": durationTexts(b.a.n.spec.Sealing.PostDelay), "assembly_delay_ns": durationTexts(builds), "import_delay_ns": durationTexts(imports)}
}
func validateApplicationSpec(spec NodeSpec, until time.Duration) error {
	invalid := func() error { return fmt.Errorf("%w: invalid application queue policy", ErrScenario) }
	switch spec.BuildQueuePolicy {
	case "":
		if spec.BuildDoneResult != "" || spec.Sealing != nil {
			return invalid()
		}
	case BuildQueueSerial:
		if spec.BuildDoneResult != BuildDoneFails && spec.BuildDoneResult != BuildDoneSubmits || spec.Sealing != nil {
			return invalid()
		}
	case BuildQueueSealing:
		if spec.BuildDoneResult != "" || spec.Sealing == nil || spec.Sealing.Selection != SealingSeeded || spec.Sealing.ResultCapacity < 1 || spec.Sealing.ResultCapacity > 1024 {
			return invalid()
		}
		for _, samples := range [][]time.Duration{spec.Sealing.CallDelay, spec.Sealing.PostDelay, spec.BuildDelay, spec.ImportDelay} {
			if len(samples) > 256 {
				return invalid()
			}
			for _, d := range samples {
				if d < 0 || d > until {
					return invalid()
				}
			}
		}
	default:
		return invalid()
	}
	return nil
}
