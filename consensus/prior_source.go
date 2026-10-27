package consensus

import (
	"errors"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// ErrPriorHeadSource reports a source that does not describe the adopted head.
var ErrPriorHeadSource = errors.New("consensus: prior source does not match the adopted head")

// PriorHeadSource binds a historical validator lookup to one adopted header.
// Validators is nil when that lookup is unavailable; an empty non-nil set is
// a successful empty lookup. This value records application provenance, not an
// independent proof of header validity or historical membership.
type PriorHeadSource struct {
	Number     types.Height
	Hash       types.Hash
	Parent     types.Hash
	Round      types.Round
	Validators *validator.Set
}

// NewPriorHeadSource captures an immutable header identity and its sealing set.
// The caller must obtain the set for (head.Number, head.ParentHash), rather
// than the set that seals the successor. A nil set preserves unavailability.
func NewPriorHeadSource(head *types.Header, vs *validator.Set) (*PriorHeadSource, error) {
	if head == nil {
		return nil, ErrPriorHeadSource
	}
	x, err := codec.DecodeConsensusExtra(head)
	if err != nil {
		return nil, ErrPriorHeadSource
	}
	return &PriorHeadSource{
		Number: head.Number, Hash: codec.BlockHash(head), Parent: head.ParentHash,
		Round: types.RoundFromUint64(uint64(x.Round)), Validators: vs,
	}, nil
}

// MatchesLookup distinguishes the historical query from the successor query.
func (p *PriorHeadSource) MatchesLookup(number types.Height, parent types.Hash) bool {
	return p != nil && p.Number.Cmp(number) == 0 && p.Parent == parent
}

// ValidateHead checks the full lookup tuple, hash and explicit header round.
// A header hash alone cannot stand in for its committed-round field.
func (p *PriorHeadSource) ValidateHead(head *types.Header) error {
	if p == nil {
		return ErrPriorHeadSource
	}
	x, err := NewPriorHeadSource(head, p.Validators)
	if err != nil || !p.MatchesLookup(x.Number, x.Parent) || p.Hash != x.Hash || p.Round.Cmp(x.Round) != 0 {
		return ErrPriorHeadSource
	}
	return nil
}

// Copy shares only the immutable validator set and immutable integer values.
func (p *PriorHeadSource) Copy() *PriorHeadSource {
	if p == nil {
		return nil
	}
	x := *p
	return &x
}

func (st *step) bindPriorHead(head *types.Header) {
	s := st.s
	policy := types.ProposerPolicy{}
	if s.validators != nil {
		policy = s.validators.Policy()
	}
	empty, _ := validator.NewSet(nil, nil, policy)
	s.prior = priorState{validators: empty}
	p, err := NewPriorHeadSource(head, nil)
	if err == nil {
		vs, lookupErr := st.env.ValidatorsAt(p.Number, p.Parent)
		if lookupErr == nil && vs != nil {
			p.Validators = vs
			s.prior.round, s.prior.validators = p.Round, vs
			s.prior.proposal = &types.Block{Header: head.Copy()}
		}
		s.prior.source = p
	}
	for _, seals := range []map[types.Address]*Verified{s.extraPrepare, s.extraCommit} {
		for _, address := range sortedAddrs(seals) {
			v := seals[address]
			if p == nil || p.Validators == nil || v == nil || v.Msg == nil || v.Msg.View.Sequence.Cmp(p.Number) != 0 || v.Msg.View.Round.Cmp(p.Round) != 0 || v.Msg.Digest != p.Hash || !p.Validators.Contains(address) {
				delete(seals, address)
			}
		}
	}
}
