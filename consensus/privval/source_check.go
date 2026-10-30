package privval

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

type SourceLimits struct{ Lifetimes, Operations, Records, Bytes uint64 }
type SourceCheck struct {
	Status, Reason, Scope, PhysicalStatus                  string
	Lifetimes, Operations, Signed, Reused, Refused, Writes uint64
}

var ErrSource = errors.New("privval: inconsistent public signing source")

// ValidateSource checks supported metadata shapes, never signing rules.
func ValidateSource(s Source) error {
	if s.Version != SourceVersion && s.Version != DomainSourceVersion || s.BadBlockReleased > 1 || s.Reused > 1 || s.WriteAttempted > 1 {
		return ErrSource
	}
	if s.Version == SourceVersion && len(s.DomainBytes) != 0 {
		return ErrSource
	}
	if s.Version == DomainSourceVersion && len(s.DomainBytes) == 0 && s.Unavailable != "domain_declaration_unavailable" {
		return ErrSource
	}
	if s.Unavailable == "domain_declaration_unavailable" && (s.Version != DomainSourceVersion || len(s.DomainBytes) != 0) {
		return ErrSource
	}
	if s.Version == DomainSourceVersion && len(s.DomainBytes) != 0 {
		if _, err := sourceDomain(s); err != nil {
			return fmt.Errorf("%w: %w", ErrSource, err)
		}
	}
	switch s.Action {
	case "initial", "vote", "init_floor", "clear_floor":
	default:
		return ErrSource
	}
	switch s.Result {
	case "ok", "below_floor", "double_sign", "state_not_empty", "persist_error", "other_error":
	default:
		return ErrSource
	}
	switch s.WriteResult {
	case "", "ok", "failed":
	default:
		return ErrSource
	}
	if s.WriteAttempted == 0 && (len(s.Write) > 0 || s.WriteResult != "") || s.WriteAttempted == 1 && s.WriteResult == "" {
		return ErrSource
	}
	switch s.Unavailable {
	case "", "namespace_missing", "metadata_exhausted", "inspection_limits_required", "record_limit", "byte_limit", "state_encoding", "request_encoding", "domain_declaration_unavailable":
	default:
		return ErrSource
	}
	if s.Unavailable == "" && (s.Ref.Namespace == "" || s.Ref.Signer == 0 || s.Ref.Sequence == 0 || len(s.Before) == 0 || len(s.After) == 0) {
		return ErrSource
	}
	return nil
}

type sourceLifetimeKey struct {
	namespace string
	signer    uint64
}

// CheckSources independently applies public signing-state rules to a retained
// mutex-ordered prefix. It never calls a signer or the runtime state transition
// helpers. Initial logical state and identity are conditional input witnesses;
// the atomic-write return does not establish physical filesystem durability.
func CheckSources(sources []Source, limits SourceLimits) (SourceCheck, error) {
	report := SourceCheck{Status: "unavailable", Scope: "signer_public_state_on_initial_witness", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (SourceCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (SourceCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrSource, reason)
	}
	if limits.Lifetimes == 0 || limits.Operations == 0 || limits.Records == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(sources)) > limits.Operations {
		return unavailable("operation_limit")
	}
	groups := map[sourceLifetimeKey][]Source{}
	var span uint64
	for _, s := range sources {
		for _, b := range [][]byte{s.BLSPublicKey, s.Before, s.After, s.Request, s.SealData, s.Signature, s.Seal, s.Write, []byte(s.Floor), []byte(s.Ref.Namespace), s.DomainBytes} {
			if uint64(len(b)) > limits.Bytes-span {
				return unavailable("byte_limit")
			}
			span += uint64(len(b))
		}
		if s.Version != SourceVersion && s.Version != DomainSourceVersion {
			return unavailable("source_version_unsupported")
		}
		if err := ValidateSource(s); errors.Is(err, types.ErrRoundChangeDomainVersion) {
			return unavailable("domain_version_unsupported")
		} else if err != nil {
			return bad("invalid_source_shape")
		}
		if s.Unavailable != "" {
			return unavailable("source_" + s.Unavailable)
		}
		key := sourceLifetimeKey{s.Ref.Namespace, s.Ref.Signer}
		if _, ok := groups[key]; !ok && uint64(len(groups)) >= limits.Lifetimes {
			return unavailable("lifetime_limit")
		}
		groups[key] = append(groups[key], s)
	}
	keys := make([]sourceLifetimeKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b sourceLifetimeKey) int {
		if a.namespace < b.namespace {
			return -1
		}
		if a.namespace > b.namespace {
			return 1
		}
		if a.signer < b.signer {
			return -1
		}
		if a.signer > b.signer {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		ops := groups[key]
		slices.SortFunc(ops, func(a, b Source) int {
			if a.Ref.Sequence < b.Ref.Sequence {
				return -1
			}
			if a.Ref.Sequence > b.Ref.Sequence {
				return 1
			}
			return 0
		})
		var previous []byte
		for i, s := range ops {
			if s.Ref.Sequence != uint64(i)+1 {
				if i > 0 && s.Ref.Sequence == ops[i-1].Ref.Sequence {
					return bad("source_sequence_repeated")
				}
				return unavailable("source_sequence_gap")
			}
			if s.Address != ops[0].Address || !bytes.Equal(s.BLSPublicKey, ops[0].BLSPublicKey) || s.Version != ops[0].Version || !bytes.Equal(s.DomainBytes, ops[0].DomainBytes) {
				return bad("source_identity_changed")
			}
			before, err := decodeSourceState(s, s.Before, limits.Records)
			if errors.Is(err, errSourceRecordLimit) {
				return unavailable("state_record_limit")
			}
			if err != nil {
				return bad("invalid_before_state")
			}
			if i > 0 && !bytes.Equal(previous, s.Before) {
				return bad("public_state_chain_changed")
			}
			if _, err := decodeSourceState(s, s.After, limits.Records); errors.Is(err, errSourceRecordLimit) {
				return unavailable("state_record_limit")
			} else if err != nil {
				return bad("invalid_after_state")
			}
			if i == 0 {
				if s.Action != "initial" {
					return unavailable("initial_state_missing")
				}
				if s.Result != "ok" || s.WriteAttempted != 0 || !bytes.Equal(s.Before, s.After) || len(s.Request)+len(s.SealData)+len(s.Signature)+len(s.Seal) > 0 || s.Reused != 0 || s.BadBlockReleased != 0 || s.Floor != "" || s.RequestCode != 0 {
					return bad("initial_state_changed")
				}
				report.Lifetimes++
			} else {
				if s.Action == "initial" {
					return bad("initial_state_repeated")
				}
				next, result, reused, err := independentSourceTransition(before, s)
				if err != nil {
					return bad("request_or_signature_changed")
				}
				expected, err := encodeSourceState(s, next)
				if err != nil {
					return bad("next_state_encoding")
				}
				write := result == "ok" && !reused
				if write {
					if s.WriteAttempted != 1 || !bytes.Equal(s.Write, expected) {
						return bad("original_write_changed")
					}
					if s.WriteResult == "failed" {
						expected = s.Before
						result = "persist_error"
					} else if s.WriteResult != "ok" {
						return bad("original_write_result_missing")
					}
					report.Writes++
				} else if s.WriteAttempted != 0 {
					return bad("unexpected_state_write")
				}
				if s.Result != result || s.Reused != sourceFlag(reused) || !bytes.Equal(s.After, expected) {
					return bad("public_state_decision_changed")
				}
				if result != "ok" {
					if len(s.Signature)+len(s.Seal) > 0 {
						return bad("signature_returned_on_error")
					}
					report.Refused++
				} else if reused {
					report.Reused++
				} else if s.Action == "vote" {
					report.Signed++
				}
			}
			previous = s.After
			report.Operations++
		}
	}
	if report.Operations == 0 {
		return unavailable("no_signer_sources")
	}
	report.Status = "consistent"
	return report, nil
}

// The fileState wire schema is shared; parsing, canonicalization, rule selection
// and updates below do not use decodeState, find, put, clone, prune or commit.
var errSourceRecordLimit = errors.New("public state record limit")

func decodeSourcePublicState(raw []byte, limit uint64, address types.Address) (fileState, error) {
	var f fileState
	if len(raw) == 0 || raw[0] != 1 {
		return f, ErrSource
	}
	if err := rlp.DecodeStrict(raw[1:], &f); err != nil {
		return f, err
	}
	if uint64(len(f.Records))+uint64(len(f.Commits)) > limit {
		return f, errSourceRecordLimit
	}
	if f.HasHighest > 1 || f.HasFloor > 1 || f.Highest == nil || f.Highest.Sign() < 0 || f.Floor == nil || f.Floor.Sign() < 0 || f.HasHighest == 0 && f.Highest.Sign() != 0 || f.HasFloor == 0 && f.Floor.Sign() != 0 {
		return f, ErrSource
	}
	if (len(f.Records) > 0 || len(f.Commits) > 0) && f.HasHighest == 0 {
		return f, ErrSource
	}
	for i, r := range f.Records {
		if r.Seq == nil || r.Seq.Sign() < 0 || r.Round == nil || r.Round.Sign() < 0 || r.Prepared == nil || r.Prepared.Sign() < 0 || r.HasPrepared > 1 || r.HasPrepared == 0 && r.Prepared.Sign() != 0 || r.Seq.Cmp(f.Highest) > 0 {
			return f, ErrSource
		}
		if r.Code != uint64(codec.CodePreprepare) && r.Code != uint64(codec.CodePrepare) && r.Code != uint64(codec.CodeCommit) && r.Code != uint64(codec.CodeRoundChange) {
			return f, ErrSource
		}
		if i > 0 && sourceRecordCompare(f.Records[i-1], r) >= 0 {
			return f, ErrSource
		}
		recovered, err := ecdsa.RecoverAddress(r.Payload, r.Signature)
		if err != nil || recovered != address {
			return f, ErrSource
		}
	}
	for i, c := range f.Commits {
		if c.Seq == nil || c.Seq.Sign() < 0 || c.Round == nil || c.Round.Sign() < 0 || c.Seq.Cmp(f.Highest) > 0 || i > 0 && f.Commits[i-1].Seq.Cmp(c.Seq) >= 0 {
			return f, ErrSource
		}
	}
	canonical, err := encodeSourcePublicState(f)
	if err != nil || !bytes.Equal(canonical, raw) {
		return f, ErrSource
	}
	return f, nil
}
func encodeSourcePublicState(f fileState) ([]byte, error) {
	slices.SortFunc(f.Records, sourceRecordCompare)
	slices.SortFunc(f.Commits, func(a, b fileCommit) int { return a.Seq.Cmp(b.Seq) })
	b, e := rlp.Encode(&f)
	if e != nil {
		return nil, e
	}
	return append([]byte{1}, b...), nil
}
func sourceRecordCompare(a, b fileRecord) int {
	if c := a.Seq.Cmp(b.Seq); c != 0 {
		return c
	}
	if c := a.Round.Cmp(b.Round); c != 0 {
		return c
	}
	if a.Code < b.Code {
		return -1
	}
	if a.Code > b.Code {
		return 1
	}
	return 0
}
func sourceFlag(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func independentSourceTransition(before fileState, s Source) (fileState, string, bool, error) {
	next := before
	next.Records = slices.Clone(before.Records)
	next.Commits = slices.Clone(before.Commits)
	if s.Action == "init_floor" || s.Action == "clear_floor" {
		if len(s.Request)+len(s.SealData)+len(s.Signature)+len(s.Seal) > 0 || s.Reused != 0 || s.BadBlockReleased != 0 || s.RequestCode != 0 {
			return next, "", false, ErrSource
		}
		if before.HasHighest == 1 {
			return next, "state_not_empty", false, nil
		}
		if s.Action == "init_floor" {
			n, ok := new(big.Int).SetString(s.Floor, 10)
			if !ok || n.Sign() < 0 || n.String() != s.Floor {
				return next, "", false, ErrSource
			}
			next.HasFloor, next.Floor = 1, n
		} else {
			if s.Floor != "" {
				return next, "", false, ErrSource
			}
			next.HasFloor, next.Floor = 0, new(big.Int)
		}
		return next, "ok", false, nil
	}
	if s.Action != "vote" || s.Floor != "" {
		return next, "", false, ErrSource
	}
	m, err := codec.DecodeMessage(codec.Code(s.RequestCode), s.Request)
	if err != nil {
		return next, "", false, err
	}
	canonical, err := codec.EncodeMessage(m)
	if err != nil || !bytes.Equal(canonical, s.Request) {
		return next, "", false, ErrSource
	}
	if m == nil || len(m.Signature) != 0 {
		return next, "", false, ErrSource
	}
	domain, err := sourceDomain(s)
	if err != nil {
		return next, "", false, err
	}
	payload, err := codec.SigningPayloadWithDomain(m, domain)
	if err != nil {
		return next, "", false, err
	}
	hash := keccak.Sum256(payload)
	seq, round := m.View.Sequence.Big(), m.View.Round.Big()
	if m.Code == codec.CodePrepare || m.Code == codec.CodeCommit {
		key, e := bls.DecodePublicKey(s.BLSPublicKey)
		if e != nil || len(s.SealData) == 0 {
			return next, "", false, ErrSource
		}
		seal, e := bls.DecodeSignature(m.Seal)
		if e != nil || !bls.Verify(key, s.SealData, seal) {
			return next, "", false, ErrSource
		}
	} else if len(m.Seal) != 0 {
		return next, "", false, ErrSource
	}
	if before.HasFloor == 1 && seq.Cmp(before.Floor) <= 0 {
		return next, "below_floor", false, nil
	}
	index := -1
	for i, r := range before.Records {
		if r.Code == uint64(m.Code) && r.Seq.Cmp(seq) == 0 && r.Round.Cmp(round) == 0 {
			index = i
			break
		}
	}
	if index >= 0 && before.Records[index].Payload == hash {
		old := before.Records[index]
		if !bytes.Equal(s.Signature, old.Signature) || !bytes.Equal(s.Seal, old.Seal) {
			return next, "", false, ErrSource
		}
		return next, "ok", true, nil
	}
	if before.HasHighest == 1 && seq.Cmp(before.Highest) < 0 {
		return next, "double_sign", false, nil
	}
	if m.Code == codec.CodeRoundChange {
		released := s.BadBlockReleased == 1 && m.PreparedRound == nil
		if !released {
			for _, c := range before.Commits {
				if c.Seq.Cmp(seq) == 0 && (m.PreparedRound == nil || m.PreparedRound.Big().Cmp(c.Round) < 0) {
					return next, "double_sign", false, nil
				}
			}
			if index >= 0 {
				old := before.Records[index]
				if old.HasPrepared == 1 && (m.PreparedRound == nil || m.PreparedRound.Big().Cmp(old.Prepared) < 0) {
					return next, "double_sign", false, nil
				}
			}
		}
	} else if index >= 0 {
		return next, "double_sign", false, nil
	}
	if s.Result == "ok" {
		if ecdsa.CheckSigner(payload, s.Signature, s.Address) != nil || !bytes.Equal(s.Seal, m.Seal) {
			return next, "", false, ErrSource
		}
	}
	// A failed write returns no signature. The attempted public state still
	// contains the original generated signature, which is verified separately.
	signature, seal := s.Signature, s.Seal
	if s.WriteResult == "failed" {
		attempted, e := decodeSourceState(s, s.Write, ^uint64(0))
		if e != nil {
			return next, "", false, e
		}
		found := false
		for _, r := range attempted.Records {
			if r.Code == uint64(m.Code) && r.Seq.Cmp(seq) == 0 && r.Round.Cmp(round) == 0 && r.Payload == hash {
				signature, seal = r.Signature, r.Seal
				found = true
				break
			}
		}
		if !found || !bytes.Equal(seal, m.Seal) {
			return next, "", false, ErrSource
		}
	}
	r := fileRecord{Code: uint64(m.Code), Seq: seq, Round: round, Payload: hash, Signature: signature, Seal: seal, Prepared: new(big.Int)}
	if m.Code == codec.CodeRoundChange && m.PreparedRound != nil {
		r.HasPrepared, r.Prepared = 1, m.PreparedRound.Big()
	}
	if index >= 0 {
		next.Records[index] = r
	} else {
		next.Records = append(next.Records, r)
	}
	if m.Code == codec.CodeCommit {
		found := false
		for i, c := range next.Commits {
			if c.Seq.Cmp(seq) == 0 {
				if c.Round.Cmp(round) < 0 {
					next.Commits[i].Round = round
				}
				found = true
				break
			}
		}
		if !found {
			next.Commits = append(next.Commits, fileCommit{seq, round})
		}
	}
	if next.HasHighest == 0 || seq.Cmp(next.Highest) > 0 {
		next.HasHighest, next.Highest = 1, seq
	}
	floor := new(big.Int).Sub(next.Highest, big.NewInt(1))
	next.Records = slices.DeleteFunc(next.Records, func(r fileRecord) bool { return r.Seq.Cmp(floor) < 0 })
	next.Commits = slices.DeleteFunc(next.Commits, func(c fileCommit) bool { return c.Seq.Cmp(floor) < 0 })
	return next, "ok", false, nil
}
