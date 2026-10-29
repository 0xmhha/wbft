package consensus

import (
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

const validatorStartInterval = time.Second

// AdoptedView observes retained state, including a suspended previous view.
// It is not production authority; callers must separately check readiness.
func (s *State) AdoptedView() (types.View, bool) {
	if s.cur == nil {
		return types.View{}, false
	}
	return s.cur.view, true
}

// RestoreBuildRequest returns only the actual current unsatisfied build
// intent of the selected profile. It does not replay historical effects.
func (s *State) RestoreBuildRequest() *RequestBuild {
	c := s.cur
	if !s.opt.Improvements.Has(DeferValidatorStart) || !s.running || s.validatorStart != nil ||
		c == nil || s.state != AcceptRequest || s.validatorBuild == nil || s.validatorBuildView.Cmp(c.view) != 0 ||
		c.pendingRequest != nil || c.preprepare != nil || c.preparedBlock != nil || c.preprepareSentValid {
		return nil
	}
	request := *s.validatorBuild
	return &request
}

type validatorStartState struct {
	target            types.Height
	parent            types.Hash
	round             types.Round
	cause             string
	reason            string
	live              bool
	resumeRoundChange bool
}

// ValidatorStartWait describes local readiness, not a new consensus view.
// An unavailable set is different from a successfully read empty set.
type ValidatorStartWait struct {
	Target              types.Height
	Parent              types.Hash
	RequestedRound      types.Round
	Cause               string
	Reason              string
	Generation          uint64
	Live                bool
	RoundChangeOnResume bool
}

// ValidatorStartWait returns an independent local readiness observation.
func (s *State) ValidatorStartWait() *ValidatorStartWait {
	p := s.validatorStart
	if p == nil {
		return nil
	}
	return &ValidatorStartWait{Target: p.target, Parent: p.parent,
		RequestedRound: p.round, Cause: p.cause, Reason: p.reason,
		Generation: s.gen[ValidatorStartTimer], Live: p.live,
		RoundChangeOnResume: p.resumeRoundChange}
}

func (st *step) deferValidatorStart(head HeadInfo, round types.Round, cause string) {
	s := st.s
	p := &validatorStartState{target: head.Header.Number.AddUint64(1),
		parent: codec.BlockHash(head.Header), round: round, cause: cause,
		reason: "validator_set_unavailable"}
	s.validatorStart = p
	s.validatorStartBarrier = true
	copy(s.validatorStartFloor[:], s.gen[:4])
	// Cancelling authority does not erase the old round or its prepared pair.
	s.roundLive, s.retryLive, s.futureLive, s.roundProposalLive = false, false, false, false
	st.emit(CancelTimers{Kinds: TimerKinds(s.opt.Improvements)})
	st.armValidatorStart()
}

func (st *step) armValidatorStart() {
	s := st.s
	p := s.validatorStart
	if s.gen[ValidatorStartTimer] == math.MaxUint64 {
		p.reason = "validator_start_generation_exhausted"
	} else {
		s.gen[ValidatorStartTimer]++
		p.live = true
		st.emit(ArmTimer{Kind: ValidatorStartTimer,
			View: types.View{Sequence: p.target, Round: p.round}, Round: p.round,
			Duration: validatorStartInterval, Gen: s.gen[ValidatorStartTimer], Digest: p.parent})
	}
	st.emit(Event{Record: event.Record{Kind: event.Health,
		View:   event.ViewOf(types.View{Sequence: p.target, Round: p.round}),
		Fields: map[string]any{"what": p.reason, "parent_hash": hexHash(p.parent)}}})
}

func (st *step) validatorStartNewHead() {
	p := st.s.validatorStart
	h := st.env.Head().Header
	if h == nil || h.Number.AddUint64(1).Cmp(p.target) <= 0 {
		return
	}
	st.startNewRound(types.Round{}, causeNewHead)
}

func (st *step) validatorStartTimeout(t Timeout) {
	s := st.s
	p := s.validatorStart
	if t.Kind != ValidatorStartTimer || !p.live || t.Gen != s.gen[ValidatorStartTimer] ||
		t.View.Sequence.Cmp(p.target) != 0 || t.View.Round.Cmp(p.round) != 0 || t.Round.Cmp(p.round) != 0 {
		return
	}
	p.live = false
	h := st.env.Head().Header
	if h == nil || h.Number.AddUint64(1).Cmp(p.target) != 0 || codec.BlockHash(h) != p.parent {
		// This matching timer has actually fired. Retain the target, but
		// replace its timer so a later canonical head can resume it.
		st.armValidatorStart()
		return
	}
	newHeight := st.startNewRound(p.round, p.cause)
	if s.validatorStart != nil {
		s.validatorStart.resumeRoundChange = p.resumeRoundChange
		return
	}
	if p.resumeRoundChange && (!newHeight || !s.opt.Improvements.Has(ResetHeightState)) {
		st.broadcastRoundChange(p.round)
	}
}
