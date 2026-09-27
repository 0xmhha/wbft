// Package stepdriver drives the pure consensus core through the steps of a
// conformance vector case or of a recorded message journal, and reports the
// observable outputs per step. Scheduled events are kept in a queue addressed
// by content and are processed only when a step names them. Transport adapters
// can plug in their frame stage.
package stepdriver
