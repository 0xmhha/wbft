package eventqueue

import "slices"

// Consumer selects among unbuffered subscription channels and handles one
// received event at a time. Handling is independent of the publisher's lock
// release and return. Event payload interpretation belongs to the driver.
type Consumer struct {
	subscriptions []string
	active        string
	exited        bool
}

func NewConsumer(subscriptions ...string) (*Consumer, error) {
	seen := map[string]bool{}
	for _, id := range subscriptions {
		if id == "" || seen[id] {
			return nil, ErrTransition
		}
		seen[id] = true
	}
	return &Consumer{subscriptions: slices.Clone(subscriptions)}, nil
}

func (c *Consumer) Active() string { return c.active }
func (c *Consumer) Exited() bool   { return c.exited }

func (c *Consumer) Receive(m *Mux, id string) ([]Effect, error) {
	if c.exited {
		return nil, ErrTransition
	}
	if c.active != "" {
		return nil, ErrNotReady
	}
	p := m.posts[id]
	if p == nil || p.Phase != Delivering || !slices.Contains(c.subscriptions, p.Subscriptions[p.Next]) {
		return nil, ErrTransition
	}
	effects, err := m.Receive(id)
	if err != nil {
		return nil, err
	}
	c.active = id
	return append(effects, Effect{Kind: "handler_received", Post: id, Subscription: p.Subscriptions[p.Next]}), nil
}

func (c *Consumer) Finish() ([]Effect, error) {
	if c.exited || c.active == "" {
		return nil, ErrTransition
	}
	id := c.active
	c.active = ""
	return []Effect{{Kind: "handler_finished", Post: id}}, nil
}

// Exit chooses a closed receive case. Another ready channel may instead be
// selected with Receive; closed channels do not preempt an active handler.
func (c *Consumer) Exit(m *Mux, subscription string) ([]Effect, error) {
	if c.exited || !slices.Contains(c.subscriptions, subscription) || m.subs[subscription] == nil {
		return nil, ErrTransition
	}
	if c.active != "" || m.subs[subscription].Phase != Closed {
		return nil, ErrNotReady
	}
	c.exited = true
	return []Effect{{Kind: "handler_exited", Subscription: subscription}}, nil
}
