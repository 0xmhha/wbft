package transport

import "github.com/0xmhha/wbft/types"

// ValidationContext describes a receiver's immutable checking context. Digests
// describe ordered public validator data, not authority or signature proofs.
// Decimal views remain exact beyond machine or JSON-number precision limits.
type ValidationContext struct {
	Sequence, Round, State, PriorRound        string
	Validators, PriorValidators               types.Hash
	ValidatorsPresent, PriorValidatorsPresent bool
}

// NewValidationScopeWithContext freezes optional observation metadata. The
// returned pointer's lifetime remains the sole functional scope identity.
func NewValidationScopeWithContext(context ValidationContext) *ValidationScope {
	scope := NewValidationScope()
	scope.metadata = context
	scope.hasContext = true
	return scope
}

// Context returns a value copy, including after Close. Missing context is
// unavailable and must not be replaced by the caller's later/current context.
func (s *ValidationScope) Context() (ValidationContext, bool) {
	if s == nil {
		return ValidationContext{}, false
	}
	return s.metadata, s.hasContext
}
