// Package sim is a deterministic multi-node simulator on a manual clock. The
// same scenario, including its seed, always produces byte-identical event
// files and message journals, which tests and analysis tools can replay.
// Partition.Cut preserves symmetric partitions; DirectedCut names ordered
// sender/recipient pairs. Params.ProposerPolicy controls the proposer rotation
// rule used by the simulated chain, with zero retaining the default.
// NodeSpec.StartAfter retains a delayed first incarnation. Per-node BuildDelay
// and ImportDelay override the shared sample distributions when provided;
// empty per-node samples retain existing shared application timing.
package sim
