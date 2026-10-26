package node

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/rpc"
)

var _ rpc.ObservationBandBackend = backend{}

func (b backend) ObservationBand(q rpc.ObservationBandRequest) (*rpc.ObservationBandResult, error) {
	if err := q.Check(); err != nil {
		return nil, err
	}
	n := b.n
	out := &rpc.ObservationBandResult{Schema: "wbft-observation-band-rpc/1", Status: "UNAVAILABLE", CoreVersion: moduleVersion()}
	n.mu.Lock()
	running := n.state == started
	configured := n.cfg.Observation != nil
	if n.info.ChainID != nil {
		out.ChainID = n.info.ChainID.String()
	}
	out.GenesisHash = n.info.GenesisHash.String()
	var r *observationRuntime
	if n.view != nil {
		r = n.view.observation
	}
	n.mu.Unlock()
	if !running {
		out.Reason = "node_not_running"
		return out, nil
	}
	if !configured {
		out.Status = "DISABLED"
		return out, nil
	}
	if r == nil || r.engine == nil {
		out.Reason = "observation_runtime_unavailable"
		return out, nil
	}
	out.ChainID = r.cfg.Policy.ChainID.String()
	out.GenesisHash = r.cfg.Policy.GenesisHash.String()
	policy, err := q.Policy(r.cfg.Retention)
	if err != nil {
		return nil, err
	}
	// Capture the application head outside both node and observation locks.
	head := n.d.App.Head()
	if head == nil {
		out.Reason = "application_head_unavailable"
		return out, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unavailable != nil {
		out.Reason = "observation_state_unavailable"
		return out, nil
	}
	if head.Number.Cmp(r.cfg.Policy.Activation) < 0 {
		out.Status = "BEFORE_ACTIVATION"
		return out, nil
	}
	if r.state == nil {
		out.Reason = "observation_state_unavailable"
		return out, nil
	}
	if r.anchor != codec.BlockHash(head) || r.state.Height().Cmp(head.Number) != 0 {
		out.Reason = "observation_tip_not_current"
		return out, nil
	}
	diagnostic, err := r.engine.DiagnoseRecent(r.state, q.Address, q.View, policy)
	if err != nil || diagnostic.CarrierHash != r.anchor.String() {
		out.Reason = "observation_state_unavailable"
		return out, nil
	}
	out.Status = "AVAILABLE"
	out.VerificationScope = "node_adopted_observation_state"
	out.Diagnostic = diagnostic
	return out, nil
}
