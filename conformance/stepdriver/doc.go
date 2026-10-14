// Package stepdriver drives the pure consensus core through conformance vectors
// and retained message journals. Recorded-order replay consumes scheduled inputs
// only at their source steps. Timed experiments instead process actual Schedule
// outputs and recorded signing results in the runner's internal FIFO order, and
// regenerate expiries through the shared manual clock and runner timer queue.
// Timed experiments expose their assumptions and never manufacture source steps
// or application/signing answers.
package stepdriver
