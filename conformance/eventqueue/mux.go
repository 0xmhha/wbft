// Package eventqueue models typed, unbuffered event delivery. A driver selects
// runnable operations explicitly. Post timestamps are preserved observations,
// not scheduling priorities, and a rendezvous does not complete event handling.
package eventqueue

import (
	"errors"
	"slices"
	"time"
)

var (
	ErrTransition = errors.New("eventqueue: invalid transition")
	ErrNotReady   = errors.New("eventqueue: operation blocked")
)

type Event struct {
	ID, Kind string
	Stamp    time.Time
}

type PostPhase string

const (
	Called      PostPhase = "called"
	Snapshotted PostPhase = "snapshotted"
	Delivering  PostPhase = "delivering"
	Releasing   PostPhase = "releasing"
	Returning   PostPhase = "returning"
	Returned    PostPhase = "returned"
)

type ClosePhase string

const (
	Open     ClosePhase = "open"
	Signaled ClosePhase = "signaled"
	Joining  ClosePhase = "joining"
	Closed   ClosePhase = "closed"
)

type Effect struct {
	Kind, Post, Subscription string
	Rejected                 bool
}

type PostState struct {
	Event         Event
	Phase         PostPhase
	Subscriptions []string
	Next          int
	Rejected      bool
}

type SubscriptionState struct {
	ID       string
	Created  time.Time
	Kinds    []string
	Attached bool
	Phase    ClosePhase
	Readers  int
}

// Mux has no internal goroutines or clock. Its owner serializes driver steps.
// Subscription IDs identify instances and cannot be reused after a restart.
// Event payloads and handler execution remain the driver's responsibility.
type Mux struct {
	subs              map[string]*SubscriptionState
	byKind            map[string][]string
	posts             map[string]*PostState
	stopping, stopped bool
	stopOrder         []string
	stopNext          int
}

func New() *Mux {
	return &Mux{subs: map[string]*SubscriptionState{}, byKind: map[string][]string{}, posts: map[string]*PostState{}}
}

func (m *Mux) Subscription(id string) (SubscriptionState, bool) {
	s, ok := m.subs[id]
	if !ok {
		return SubscriptionState{}, false
	}
	out := *s
	out.Kinds = slices.Clone(s.Kinds)
	return out, true
}

func (m *Mux) Post(id string) (PostState, bool) {
	p, ok := m.posts[id]
	if !ok {
		return PostState{}, false
	}
	out := *p
	out.Subscriptions = slices.Clone(p.Subscriptions)
	return out, true
}

func (m *Mux) Stopping() bool { return m.stopping }
func (m *Mux) Stopped() bool  { return m.stopped }

// Subscribe adds one unbuffered channel shared by the supplied event kinds.
// A stopped mux returns a closed channel without registering the subscription.
func (m *Mux) Subscribe(id string, created time.Time, kinds ...string) ([]Effect, error) {
	if id == "" || m.subs[id] != nil {
		return nil, ErrTransition
	}
	if m.stopping {
		return nil, ErrNotReady
	}
	seen := map[string]bool{}
	for _, kind := range kinds {
		if kind == "" || !m.stopped && seen[kind] {
			return nil, ErrTransition
		}
		seen[kind] = true
	}
	s := &SubscriptionState{ID: id, Created: created, Kinds: slices.Clone(kinds), Attached: !m.stopped, Phase: Open}
	if m.stopped {
		s.Phase = Closed
	} else {
		for _, kind := range kinds {
			m.byKind[kind] = append(m.byKind[kind], id)
		}
	}
	m.subs[id] = s
	return []Effect{{Kind: "subscription_added", Subscription: id}}, nil
}

// Call captures the original post timestamp before the mux read lock.
func (m *Mux) Call(event Event) ([]Effect, error) {
	if event.ID == "" || event.Kind == "" || m.posts[event.ID] != nil {
		return nil, ErrTransition
	}
	m.posts[event.ID] = &PostState{Event: event, Phase: Called}
	return []Effect{{Kind: "post_called", Post: event.ID}}, nil
}

// Snapshot takes a fixed subscriber list. Stop may block this step, but never
// changes the outcome of posts that already captured their subscriber list.
func (m *Mux) Snapshot(id string) ([]Effect, error) {
	p := m.posts[id]
	if p == nil || p.Phase != Called {
		return nil, ErrTransition
	}
	if m.stopping {
		return nil, ErrNotReady
	}
	p.Rejected = m.stopped
	if p.Rejected {
		p.Phase = Returning
		return []Effect{{Kind: "post_rejected", Post: id, Rejected: true}}, nil
	}
	p.Subscriptions = slices.Clone(m.byKind[p.Event.Kind])
	p.Phase = Snapshotted
	if len(p.Subscriptions) == 0 {
		p.Phase = Returning
	}
	return []Effect{{Kind: "post_snapshot", Post: id}}, nil
}

// Enter checks stale time before acquiring a delivery read lock. Once a close
// writer is waiting, new readers wait until the actual channel has closed.
func (m *Mux) Enter(id string) ([]Effect, error) {
	p := m.posts[id]
	if p == nil || p.Phase != Snapshotted || p.Next >= len(p.Subscriptions) {
		return nil, ErrTransition
	}
	s := m.subs[p.Subscriptions[p.Next]]
	if s.Created.After(p.Event.Stamp) {
		m.advance(p)
		return []Effect{{Kind: "stale_dropped", Post: id, Subscription: s.ID}}, nil
	}
	if s.Phase == Joining {
		return nil, ErrNotReady
	}
	s.Readers++
	p.Phase = Delivering
	return []Effect{{Kind: "delivery_entered", Post: id, Subscription: s.ID}}, nil
}

// Receive is an explicit unbuffered rendezvous. During close, a reader already
// inside select may choose either this receive or Drop. No buffered receipt or
// handler completion is implied, and the publisher still owns its read lock.
func (m *Mux) Receive(id string) ([]Effect, error) {
	p, s := m.delivery(id)
	if p == nil {
		return nil, ErrTransition
	}
	if s.Phase == Closed {
		return nil, ErrNotReady
	}
	p.Phase = Releasing
	return []Effect{{Kind: "delivered", Post: id, Subscription: s.ID}}, nil
}

func (m *Mux) Drop(id string) ([]Effect, error) {
	p, s := m.delivery(id)
	if p == nil {
		return nil, ErrTransition
	}
	if s.Phase == Open {
		return nil, ErrNotReady
	}
	p.Phase = Releasing
	return []Effect{{Kind: "closing_dropped", Post: id, Subscription: s.ID}}, nil
}

// Release is separate from the rendezvous: a close cannot finish while a
// selected delivery still holds its read lock. The next subscriber is visited
// only after this release, in the original snapshot order.
func (m *Mux) Release(id string) ([]Effect, error) {
	p := m.posts[id]
	if p == nil || p.Phase != Releasing {
		return nil, ErrTransition
	}
	s := m.subs[p.Subscriptions[p.Next]]
	s.Readers--
	m.advance(p)
	return []Effect{{Kind: "delivery_released", Post: id, Subscription: s.ID}}, nil
}

func (m *Mux) Return(id string) ([]Effect, error) {
	p := m.posts[id]
	if p == nil || p.Phase != Returning {
		return nil, ErrTransition
	}
	p.Phase = Returned
	return []Effect{{Kind: "post_returned", Post: id, Rejected: p.Rejected}}, nil
}

func (m *Mux) delivery(id string) (*PostState, *SubscriptionState) {
	p := m.posts[id]
	if p == nil || p.Phase != Delivering {
		return nil, nil
	}
	return p, m.subs[p.Subscriptions[p.Next]]
}

func (m *Mux) advance(p *PostState) {
	p.Next++
	p.Phase = Snapshotted
	if p.Next == len(p.Subscriptions) {
		p.Phase = Returning
	}
}

// Remove detaches a subscriber without closing its channel. Existing post
// snapshots still contain that instance, and may rendezvous before SignalClose.
func (m *Mux) Remove(id string) ([]Effect, error) {
	s := m.subs[id]
	if s == nil {
		return nil, ErrTransition
	}
	if m.stopping {
		return nil, ErrNotReady
	}
	if !s.Attached {
		return nil, nil
	}
	for _, kind := range s.Kinds {
		ids := m.byKind[kind]
		at := slices.Index(ids, id)
		if at >= 0 {
			ids = slices.Delete(slices.Clone(ids), at, at+1)
		}
		if len(ids) == 0 {
			delete(m.byKind, kind)
		} else {
			m.byKind[kind] = ids
		}
	}
	s.Attached = false
	return []Effect{{Kind: "subscription_removed", Subscription: id}}, nil
}

func (m *Mux) SignalClose(id string) ([]Effect, error) {
	s := m.subs[id]
	if s == nil || s.Attached && (!m.stopping || m.StopCurrent() != id) {
		return nil, ErrTransition
	}
	if s.Phase == Closed {
		return nil, nil
	}
	if s.Phase != Open {
		return nil, ErrNotReady
	}
	s.Phase = Signaled
	return []Effect{{Kind: "close_signaled", Subscription: id}}, nil
}

// BeginJoin is separate from SignalClose, allowing the interval between the
// closing signal and the writer's lock attempt to admit another reader.
func (m *Mux) BeginJoin(id string) ([]Effect, error) {
	s := m.subs[id]
	if s == nil || s.Phase != Signaled {
		return nil, ErrTransition
	}
	s.Phase = Joining
	return []Effect{{Kind: "close_join_started", Subscription: id}}, nil
}

func (m *Mux) FinishClose(id string) ([]Effect, error) {
	s := m.subs[id]
	if s == nil || s.Phase != Joining {
		return nil, ErrTransition
	}
	if s.Readers != 0 {
		return nil, ErrNotReady
	}
	s.Phase = Closed
	return []Effect{{Kind: "subscription_closed", Subscription: id}}, nil
}

// BeginStop takes the mux write lock. The driver supplies a map-key iteration
// order, while subscriber order within each kind is fixed. A subscription to
// multiple kinds is visited multiple times, as in the original nested traversal.
func (m *Mux) BeginStop(kindOrder []string) ([]Effect, error) {
	if m.stopping {
		return nil, ErrNotReady
	}
	if len(kindOrder) != len(m.byKind) {
		return nil, ErrTransition
	}
	seen := map[string]bool{}
	order := []string{}
	for _, kind := range kindOrder {
		ids, ok := m.byKind[kind]
		if !ok || seen[kind] {
			return nil, ErrTransition
		}
		seen[kind] = true
		order = append(order, ids...)
	}
	m.stopping, m.stopOrder, m.stopNext = true, order, 0
	return []Effect{{Kind: "stop_started"}}, nil
}

func (m *Mux) StopCurrent() string {
	if !m.stopping || m.stopNext == len(m.stopOrder) {
		return ""
	}
	return m.stopOrder[m.stopNext]
}

func (m *Mux) AdvanceStop() ([]Effect, error) {
	id := m.StopCurrent()
	if id == "" {
		return nil, ErrTransition
	}
	if m.subs[id].Phase != Closed {
		return nil, ErrNotReady
	}
	m.stopNext++
	return []Effect{{Kind: "stop_advanced", Subscription: id}}, nil
}

func (m *Mux) FinishStop() ([]Effect, error) {
	if !m.stopping || m.stopNext != len(m.stopOrder) {
		return nil, ErrNotReady
	}
	for _, ids := range m.byKind {
		for _, id := range ids {
			m.subs[id].Attached = false
		}
	}
	m.byKind = map[string][]string{}
	m.stopping, m.stopped = false, true
	return []Effect{{Kind: "stop_finished"}}, nil
}
