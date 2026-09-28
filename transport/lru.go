package transport

import "container/list"

// lru is a least-recently-used set of at most size keys with a value each.
// Get and Add refresh a key.
type lru[K comparable, V any] struct {
	size  int
	order *list.List // front: most recent
	items map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](size int) *lru[K, V] {
	return &lru[K, V]{size: size, order: list.New(), items: make(map[K]*list.Element)}
}

// Get returns the value of k and refreshes it.
func (c *lru[K, V]) Get(k K) (V, bool) {
	if e, ok := c.items[k]; ok {
		c.order.MoveToFront(e)
		return e.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// Contains reports whether k is present without refreshing it.
func (c *lru[K, V]) Contains(k K) bool {
	_, ok := c.items[k]
	return ok
}

// Add sets the value of k, refreshes it and evicts the least recently used
// key when the set is full.
func (c *lru[K, V]) Add(k K, v V) {
	if e, ok := c.items[k]; ok {
		e.Value.(*lruEntry[K, V]).val = v
		c.order.MoveToFront(e)
		return
	}
	c.items[k] = c.order.PushFront(&lruEntry[K, V]{key: k, val: v})
	if c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*lruEntry[K, V]).key)
	}
}

// Remove deletes k.
func (c *lru[K, V]) Remove(k K) {
	if e, ok := c.items[k]; ok {
		c.order.Remove(e)
		delete(c.items, k)
	}
}

// Len returns the number of keys.
func (c *lru[K, V]) Len() int { return c.order.Len() }
