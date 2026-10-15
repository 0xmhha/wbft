package sim

import (
	"errors"

	"github.com/0xmhha/wbft/consensus/runner"
)

// Engine actions use the existing runner, signer, WAL, transport and clocks.
// The application keeps importing blocks while consensus is paused, as when
// a node synchronises. A full node stop still closes its incarnation's logs.
func (n *node) requestEngineAction(action string) {
	if n.alive && !n.down && n.r != nil {
		n.engineActions = append(n.engineActions, action)
	}
}

// A physical Stop waits behind synchronous finalization. The manual runner
// returns ErrFinalizePending instead, so retain ordered control actions until
// the scheduled application completion makes the same boundary runnable.
func (n *node) pumpEngineActions() bool {
	did := false
	for len(n.engineActions) > 0 && n.alive && !n.down && n.r != nil {
		action := n.engineActions[0]
		var err error
		if !n.guard(func() {
			switch action {
			case ActionEngineStop:
				if n.r.Running() {
					err = n.r.Stop()
				}
			case ActionEngineStart:
				if !n.r.Running() {
					err = n.r.Start(n.s.ctx, n.app.chain.head.Header.Number.AddUint64(1))
					if err == nil {
						info := n.r.LastReplay()
						n.s.replays = append(n.s.replays, info)
						if info.Stopped != "" {
							n.s.violate("replay", n.v.address, "%s", info.Stopped)
						}
					}
				}
			}
		}) {
			return did
		}
		if errors.Is(err, runner.ErrFinalizePending) || errors.Is(err, runner.ErrProcessingPending) {
			return did
		}
		n.engineActions = n.engineActions[1:]
		did = true
		if err != nil {
			n.s.violate("engine_lifecycle", n.v.address, "%s: %v", action, err)
		}
	}
	return did
}
