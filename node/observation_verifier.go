package node

import "github.com/0xmhha/wbft/chain/header"

// ObservationVerifier supplies the active observation gate to an application's
// full header verifier. Nil denotes disabled or not-yet-started configuration.
// An application configured for observations must refuse verification until a
// non-nil gate is available. Other ordered header rules remain mandatory.
func (n *Node) ObservationVerifier() header.ObservationVerifier {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.view == nil || n.view.observation == nil {
		return nil
	}
	return n.view.observation
}
