package journal

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
)

type RestoreSignerCheck struct {
	Status, Reason, Scope, PhysicalStatus string
	Calls, WALOwnBindings                 uint64
	Signer                                privval.SourceCheck
}
type signerExpected struct {
	source *CoreStepRec
	output consensus.Broadcast
	seen   bool
}
type indexedSigner struct {
	source *SignerRec
	index  int
	writer string
}
type walOwnPosition struct {
	namespace            string
	log, segment, offset uint64
}
type walOwnWitness struct {
	sequence uint64
	index    int
	bytes    []byte
	frame    []byte
}

// CheckRestoredSignerSources joins independently checked public signing state
// to actual core outputs, runner calls and later original WAL readable frames.
// Roots remain conditional; application execution and physical persistence are
// not accepted by this component.
func CheckRestoredSignerSources(records []Record, coreLimits CoreSourceLimits, signerLimits privval.SourceLimits) (RestoreCheck, CoreSourceCheck, RestoreEffectsCheck, RestoreSignerCheck, error) {
	restore, core, effects, err := CheckRestoredBoundarySources(records, coreLimits)
	report := RestoreSignerCheck{Status: "unavailable", Scope: "restored_boundary_signer_state_and_own_wal", PhysicalStatus: "unavailable"}
	if err != nil || restore.Status != "consistent" || core.Status != "consistent" || effects.Status != "consistent" {
		report.Reason = "restore_boundary_not_reconstructed"
		return restore, core, effects, report, err
	}
	report, err = checkRestoreSignerCalls(records, coreLimits, signerLimits)
	if err == nil && report.Status == "consistent" {
		restore.SignerStatus = "consistent_on_initial_witness"
	}
	return restore, core, effects, report, err
}

func checkRestoreSignerCalls(records []Record, limits CoreSourceLimits, sourceLimits privval.SourceLimits) (RestoreSignerCheck, error) {
	return inspectRestoreSignerCalls(records, limits, sourceLimits, nil, 0, nil)
}

// The private capture contains checked immutable bindings, never an actor model.
func inspectRestoreSignerCalls(records []Record, limits CoreSourceLimits, sourceLimits privval.SourceLimits, budget *originBudget, span uint64, capture func(signerOriginEvidence)) (RestoreSignerCheck, error) {
	report := RestoreSignerCheck{Status: "unavailable", Scope: "restored_boundary_signer_state_and_own_wal", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (RestoreSignerCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (RestoreSignerCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrRestoreSource, reason)
	}
	var sources []privval.Source
	declaredDomains := map[string][]byte{}
	byRef := map[privval.SourceRef]indexedSigner{}
	reads := map[WALReadRef]int{}
	positions := map[walOwnPosition][]walOwnWitness{}
	writer := ""
	var retainedSpan uint64
	charge := func(n uint64) bool {
		if n > limits.Bytes-retainedSpan {
			return false
		}
		retainedSpan += n
		return true
	}
	for i, rec := range records {
		switch r := rec.Body.(type) {
		case *SegmentRec:
			writer = r.Run
			if !charge(uint64(len(r.Core.DomainBytes))) {
				return unavailable("signer_byte_limit")
			}
			if err := r.ValidateDomainIdentity(); err != nil {
				if len(r.Core.DomainBytes) == 0 || errors.Is(err, ErrDomainSourceUnsupported) {
					return unavailable("round_change_domain_context_unavailable")
				}
				return bad("round_change_domain_identity_changed")
			}
			if old, ok := declaredDomains[writer]; ok && !bytes.Equal(old, r.Core.DomainBytes) {
				return bad("signer_writer_domain_changed")
			}
			declaredDomains[writer] = bytes.Clone(r.Core.DomainBytes)
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindSigner) || k.Kind == uint64(KindSignerCall)) {
					return unavailable("signer_source_gap")
				}
			}
		case *SignerRec:
			if !charge(uint64(size(rec))) {
				return unavailable("signer_byte_limit")
			}
			if r.Source.Ref.Namespace != writer {
				return bad("signer_writer_changed")
			}
			if err := matchSignerDomain(r.Source, declaredDomains[writer]); err != nil {
				if errors.Is(err, ErrSignerSourceUnsupported) {
					return unavailable("signer_domain_profile_unavailable")
				}
				return bad("signer_domain_changed")
			}
			if _, ok := byRef[r.Source.Ref]; ok {
				return bad("signer_operation_reused")
			}
			byRef[r.Source.Ref] = indexedSigner{r, i, writer}
			sources = append(sources, r.Source)
		case *WALReadRec:
			ref := WALReadRef{r.Source.Namespace, r.Source.Log, r.Source.Sequence}
			reads[ref] = i
			for _, f := range r.Source.Frames {
				if !charge(uint64(len(f.Bytes))) {
					return unavailable("signer_byte_limit")
				}
				if len(f.Bytes) < 10 {
					return bad("invalid_wal_source")
				}
				if f.Bytes[8] == 1 && f.Bytes[9] == 4 {
					key := walOwnPosition{r.Source.Namespace, r.Source.Log, f.Position.Segment, uint64(f.Position.Offset)}
					positions[key] = append(positions[key], walOwnWitness{r.Source.Sequence, i, f.Bytes[10:], f.Bytes})
				}
			}
		}
	}
	var err error
	if budget != nil {
		if err = budget.lease(span, 4096, true); err != nil {
			return unavailable(err.Error())
		}
		allocated, e := originSignerQuota(budget, sources)
		if e != nil {
			if errorsIsOrigin(e) {
				return bad(e.Error())
			}
			return unavailable(e.Error())
		}
		sourceLimits = privval.SourceLimits{Lifetimes: min(sourceLimits.Lifetimes, allocated.Lifetimes), Operations: min(sourceLimits.Operations, allocated.Operations), Records: min(sourceLimits.Records, allocated.Records), Bytes: min(sourceLimits.Bytes, allocated.Bytes)}
	}
	report.Signer, err = privval.CheckSources(sources, sourceLimits)
	if err != nil {
		return bad("signer_" + report.Signer.Reason)
	}
	if report.Signer.Status != "consistent" {
		return unavailable("signer_" + report.Signer.Reason)
	}
	if budget != nil {
		if err = budget.lease(span, 16, true); err != nil {
			return unavailable(err.Error())
		}
	}
	_, seeds, err := reconstructRestoreSourcesBudget(records, limits, budget)
	if err != nil {
		return bad("restore_reconstruction_changed")
	}
	expected := map[internalOutputKey]*signerExpected{}
	if budget != nil {
		if err = budget.lease(span, 16, true); err != nil {
			return unavailable(err.Error())
		}
	}
	inspected, _, err := inspectCoreSourceProfileBudget(records, limits, func(writer string, source *CoreStepRec, outputs []consensus.Output) {
		for i, out := range outputs {
			if b, ok := out.(consensus.Broadcast); ok {
				expected[internalOutputKey{appCoreKey{writer, source.EngineRun, source.Step}, uint64(i) + 1}] = &signerExpected{source: source, output: b}
			}
		}
	}, nil, seeds, false, nil, budget)
	if err != nil {
		return bad("core_" + inspected.Reason)
	}
	if inspected.Status != "consistent" {
		return unavailable("core_" + inspected.Reason)
	}
	boundOwn := map[walOwnPosition]bool{}
	authenticatedFrames := map[walOwnPosition][]byte{}
	used := map[privval.SourceRef]bool{}
	writer = ""
	for position, rec := range records {
		switch r := rec.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *SignerCallRec:
			if !charge(uint64(size(rec))) {
				return unavailable("signer_byte_limit")
			}
			if !validSignerCall(r) {
				return bad("invalid_signer_call")
			}
			if r.Unavailable != "" {
				return unavailable("signer_call_" + r.Unavailable)
			}
			if r.Result != "sent" || r.WALPresent != 1 || r.WALWritten != 1 {
				return unavailable("nonstored_signer_call_not_supported")
			}
			key := internalOutputKey{appCoreKey{writer, r.EngineRun, r.Step}, r.Output}
			proof := expected[key]
			if proof == nil || proof.seen {
				return bad("signer_core_output_changed")
			}
			b := proof.output
			if b.Msg == nil {
				return unavailable("unsigned_core_message_missing")
			}
			unsigned := *b.Msg
			unsigned.Signature, unsigned.Seal = nil, nil
			request, err := codec.EncodeMessage(&unsigned)
			if err != nil {
				return unavailable("unsigned_core_message_encoding")
			}
			if r.RequestCode != uint64(unsigned.Code) || !bytes.Equal(r.Request, request) || !bytes.Equal(r.SealData, b.SealData) || r.BadBlockReleased != boolUint(b.BadBlockReleased) {
				return bad("signer_request_changed")
			}
			if r.Mono < uint64(proof.source.Entry.Mono) || r.Mono > uint64(proof.source.Observed.Mono) {
				return bad("signer_call_outside_core_step")
			}
			signer, ok := byRef[r.Source]
			if !ok {
				return unavailable("signer_operation_missing")
			}
			if signer.writer != writer || signer.index >= position || used[r.Source] {
				return bad("signer_operation_owner_or_order_changed")
			}
			used[r.Source] = true
			s := signer.source.Source
			if err := matchSignerDomain(s, proof.source.DomainBytes); err != nil {
				if errors.Is(err, ErrSignerSourceUnsupported) {
					return unavailable("signer_domain_profile_unavailable")
				}
				return bad("signer_core_domain_changed")
			}
			if s.Action != "vote" || s.Result != "ok" || s.RequestCode != r.RequestCode || s.Address != proof.source.CoreSelf || s.BadBlockReleased != r.BadBlockReleased || s.Reused != r.Reused || !bytes.Equal(s.SealData, r.SealData) || !bytes.Equal(s.Signature, r.Signature) || !bytes.Equal(s.Seal, r.Seal) {
				return bad("signer_result_changed")
			}
			if unsigned.Code == codec.CodePrepare || unsigned.Code == codec.CodeCommit {
				if b.Validators == nil {
					return unavailable("signer_vote_authority_missing")
				}
				member, ok := b.Validators.IndexOf(s.Address)
				if !ok || !bytes.Equal(b.Validators.At(member).BLSPublicKey, s.BLSPublicKey) {
					return bad("signer_vote_authority_changed")
				}
			}
			prepared, err := codec.DecodeMessage(codec.Code(s.RequestCode), s.Request)
			if err != nil {
				return bad("signer_prepared_request_changed")
			}
			prepared.Signature, prepared.Seal = nil, nil
			unsealed, err := codec.EncodeMessage(prepared)
			if err != nil || !bytes.Equal(unsealed, r.Request) {
				return bad("signer_prepared_request_changed")
			}
			signed := unsigned
			signed.Signature, signed.Seal = r.Signature, r.Seal
			payload, err := codec.EncodeMessage(&signed)
			if err != nil || !bytes.Equal(payload, r.Payload) {
				return bad("signed_wal_payload_changed")
			}
			readIndex, ok := reads[r.WAL]
			if !ok {
				return unavailable("own_wal_log_source_missing")
			}
			if readIndex >= position || r.WAL.Namespace != writer {
				return bad("own_wal_log_owner_or_order_changed")
			}
			matched := false
			for _, w := range positions[walOwnPosition{r.WAL.Namespace, r.WAL.Log, r.Segment, r.Offset}] {
				if w.index <= position || w.sequence <= r.WAL.Sequence {
					continue
				}
				var own restoreOwnWire
				if rlp.DecodeStrict(w.bytes, &own) != nil {
					return bad("own_wal_record_invalid")
				}
				if own.Refused != 0 || own.Code != r.RequestCode || !bytes.Equal(own.Payload, r.Payload) {
					return bad("own_wal_frame_changed")
				}
				authenticatedFrames[walOwnPosition{r.WAL.Namespace, r.WAL.Log, r.Segment, r.Offset}] = w.frame
				matched = true
				break
			}
			if !matched {
				return unavailable("later_original_own_wal_frame_missing")
			}
			boundOwn[walOwnPosition{r.WAL.Namespace, r.WAL.Log, r.Segment, r.Offset}] = true
			proof.seen = true
			report.Calls++
			report.WALOwnBindings++
		}
	}
	for _, proof := range expected {
		if !proof.seen {
			return unavailable("signer_call_missing")
		}
	}
	if capture != nil {
		needs := map[walOwnPosition]WALReadRef{}
		unsupported := ""
		for _, seed := range seeds {
			for _, index := range seed.ownFrames {
				f := seed.read.Source.Frames[index]
				key := walOwnPosition{seed.read.Source.Namespace, seed.read.Source.Log, f.Position.Segment, uint64(f.Position.Offset)}
				ref := WALReadRef{seed.read.Source.Namespace, seed.read.Source.Log, seed.read.Source.Sequence}
				if old, ok := needs[key]; ok && old != ref {
					unsupported = "multiple_origin_restore_reads_unsupported"
				}
				needs[key] = ref
			}
		}
		capture(signerOriginEvidence{bound: boundOwn, needs: needs, frames: authenticatedFrames, unsupported: unsupported})
	}
	for _, seed := range seeds {
		for _, index := range seed.ownFrames {
			f := seed.read.Source.Frames[index]
			if !boundOwn[walOwnPosition{seed.read.Source.Namespace, seed.read.Source.Log, f.Position.Segment, uint64(f.Position.Offset)}] {
				return unavailable("restored_original_signer_call_missing")
			}
		}
	}
	if report.Calls == 0 {
		return unavailable("no_signer_calls")
	}
	report.Status = "consistent"
	return report, nil
}
