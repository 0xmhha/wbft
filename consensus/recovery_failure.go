package consensus

// RecoveryFailure identifies the first failing phase of message recovery.
// It is diagnostic classification, not proof that an input was accepted.
// In particular, membership failures depend on the authority context and
// cannot be reused in another context.
type RecoveryFailure uint8

const (
	RecoverySucceeded RecoveryFailure = iota
	RecoveryDecode
	RecoveryEncoding
	RecoverySignature
	RecoveryMembership
)
