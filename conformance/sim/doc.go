// Package sim is a deterministic multi-node simulator on a manual clock. The
// same scenario, including its seed, always produces byte-identical event
// files and message journals, which tests and analysis tools can replay.
// Partition.Cut preserves symmetric partitions; DirectedCut names ordered
// sender/recipient pairs. Params.ProposerPolicy controls the proposer rotation
// rule used by the simulated chain, with zero retaining the default.
// NodeSpec.StartAfter retains a delayed first incarnation. Per-node BuildDelay
// and ImportDelay override the shared sample distributions when provided;
// empty per-node samples retain existing shared application timing.
//
// BuildQueueSerial selects a latest-pending worker whose assembly return and
// Done behavior are explicit. BuildQueueSealing instead selects unbuffered
// work/task handoffs, asynchronous sealing mutex ownership, independent request
// posting and bounded commit/result/head channels. Its SealingProfile requires
// an explicit scheduler and result capacity. It assembles an empty body on the
// head selected by the worker; it does not execute transactions or infer their
// interrupt checkpoints. CallDelay and PostDelay independently control caller
// return and request posting. A caller return never implies a sealed result.
//
// The sealing scheduler chooses ready actors with the scenario seed, runs them
// to idle, then advances to deadline callbacks on the shared manual clock.
// The startup declaration records this choice and the sample distributions.
// Stops retain active assembly and local imports until their sampled returns;
// a crash drops them without inventing completion. These are declared fake
// application models, not fitted evidence of a physical process or network.
package sim
