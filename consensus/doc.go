// Package consensus is the pure consensus state machine. It takes one input at
// a time (messages, timeouts, application answers) and returns outputs
// (messages to send, timer requests, commits) without clocks, goroutines,
// randomness or I/O, so that every run can be replayed exactly.
package consensus
