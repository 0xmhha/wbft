// Package taskqueue models an unbuffered sealing-task handoff and a serial
// caller of an asynchronous sealing engine. The driver chooses ready channel
// alternatives explicitly; a successful Seal return is not a sealed result.
package taskqueue

import "errors"

var ErrTransition = errors.New("taskqueue: invalid transition")

type Request struct {
	ID   string
	Hash [32]byte
}
type Kind uint8

const (
	Received Kind = iota
	Duplicate
	CancelSeal
	Skipped
	CallSeal
	SealReturned
	Abandoned
	Exited
)

type Effect struct {
	ID     string
	Kind   Kind
	Failed bool
}

// Queue accepts one blocked producer at a time. Offer does not complete the
// unbuffered send. Receiving the next task is impossible during a Seal call,
// while the asynchronous operation may outlive that call indefinitely.
type Queue struct {
	offered, calling  *Request
	previous          [32]byte
	stopOwner         string
	exitReady, exited bool
	seen              map[string]bool
	pending           map[[32]byte]string
}

func New() *Queue { return &Queue{seen: map[string]bool{}, pending: map[[32]byte]string{}} }
func (q *Queue) OfferedID() string {
	if q.offered == nil {
		return ""
	}
	return q.offered.ID
}
func (q *Queue) CallingID() string {
	if q.calling == nil {
		return ""
	}
	return q.calling.ID
}
func (q *Queue) StopOwner() string              { return q.stopOwner }
func (q *Queue) PendingID(hash [32]byte) string { return q.pending[hash] }
func (q *Queue) Exited() bool                   { return q.exited }

func (q *Queue) Offer(r Request) error {
	if r.ID == "" || q.seen[r.ID] || q.offered != nil {
		return ErrTransition
	}
	q.seen[r.ID] = true
	q.offered = &r
	return nil
}

// Receive is one explicit select choice, including when exit is also ready.
// Duplicate hashes are tested before cancelling the previous operation. The
// initial previous hash is zero, matching an uninitialized engine hash value.
func (q *Queue) Receive(skip bool) ([]Effect, error) {
	if q.exited || q.calling != nil || q.offered == nil {
		return nil, ErrTransition
	}
	r := *q.offered
	q.offered = nil
	out := []Effect{{ID: r.ID, Kind: Received}}
	if r.Hash == q.previous {
		return append(out, Effect{ID: r.ID, Kind: Duplicate}), nil
	}
	if q.stopOwner != "" {
		out = append(out, Effect{ID: q.stopOwner, Kind: CancelSeal})
	}
	q.previous = r.Hash
	q.stopOwner = r.ID
	if skip {
		return append(out, Effect{ID: r.ID, Kind: Skipped}), nil
	}
	q.pending[r.Hash] = r.ID
	q.calling = &r
	return append(out, Effect{ID: r.ID, Kind: CallSeal}), nil
}

// Return releases only the synchronous caller. Error removes its pending task
// but preserves the previous hash and cancellation channel; success preserves
// pending state. Neither case fabricates an asynchronous sealing completion.
func (q *Queue) Return(id string, failed bool) ([]Effect, error) {
	if q.calling == nil || q.calling.ID != id {
		return nil, ErrTransition
	}
	if failed {
		delete(q.pending, q.calling.Hash)
	}
	q.calling = nil
	return []Effect{{ID: id, Kind: SealReturned, Failed: failed}}, nil
}
func (q *Queue) RequestExit() { q.exitReady = true }

// ChooseExit is distinct from making exit ready. A blocked Seal invocation
// must return first. An offered producer independently chooses Abandon or its
// rendezvous with Receive; no timestamp priority is inferred.
func (q *Queue) ChooseExit() ([]Effect, error) {
	if !q.exitReady || q.exited || q.calling != nil {
		return nil, ErrTransition
	}
	out := []Effect{}
	if q.stopOwner != "" {
		out = append(out, Effect{ID: q.stopOwner, Kind: CancelSeal})
		q.stopOwner = ""
	}
	q.exited = true
	return append(out, Effect{Kind: Exited}), nil
}
func (q *Queue) Abandon(id string) ([]Effect, error) {
	if !q.exitReady || q.offered == nil || q.offered.ID != id {
		return nil, ErrTransition
	}
	q.offered = nil
	return []Effect{{ID: id, Kind: Abandoned}}, nil
}

// Forget is driven by an independently observed pending-task cleanup. Old
// results must not delete a newer task that reused the same sealing hash.
func (q *Queue) Forget(hash [32]byte, id string) error {
	if id == "" || q.pending[hash] != id {
		return ErrTransition
	}
	delete(q.pending, hash)
	return nil
}
