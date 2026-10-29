package journal

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/types"
)

type signerOriginEvidence struct {
	bound       map[walOwnPosition]bool
	needs       map[walOwnPosition]WALReadRef
	frames      map[walOwnPosition][]byte
	unsupported string
}

type originRead struct {
	record *WALReadRec
	index  int
}
type originCall struct {
	record *SignerCallRec
	index  int
}
type signerOriginGroup struct {
	records     []Record
	span        uint64
	identity    *Identity
	reads       map[WALReadRef]originRead
	first, last *privval.Source
	calls       []originCall
	replayed    bool
	proof       signerOriginEvidence
}

func errorsIsOrigin(err error) bool {
	return errors.Is(err, ErrSignerOrigin) || errors.Is(err, ErrRestoreSource) || errors.Is(err, ErrCoreSource) || errors.Is(err, privval.ErrSource)
}

func originInconsistent(reason string) error { return fmt.Errorf("%w: %s", ErrSignerOrigin, reason) }

// originSignerQuota counts public-state entries before allocating a group's
// independent checker allowance. Its decoding lease precedes every list walk.
func originSignerQuota(b *originBudget, sources []privval.Source) (privval.SourceLimits, error) {
	quota := privval.SourceLimits{Lifetimes: 1, Operations: max(1, uint64(len(sources))), Records: 1, Bytes: 1}
	for _, s := range sources {
		stateSpans := [][]byte{s.Before, s.After}
		if len(s.Write) > 0 {
			stateSpans = append(stateSpans, s.Write)
		}
		for _, raw := range stateSpans {
			if err := b.lease(uint64(len(raw)), 4, false); err != nil {
				return quota, err
			}
			if len(raw) < 2 || raw[0] != 1 {
				return quota, originInconsistent("invalid_signer_public_state")
			}
			fields, err := rlp.ListItems(raw[1:])
			if err != nil || len(fields) != 6 {
				return quota, originInconsistent("invalid_signer_public_state")
			}
			for _, field := range fields[4:] {
				entries, err := rlp.ListItems(field)
				if err != nil {
					return quota, originInconsistent("invalid_signer_public_state")
				}
				quota.Records, err = originAdd(quota.Records, uint64(len(entries)))
				if err != nil {
					return quota, err
				}
			}
		}
		for _, n := range []uint64{uint64(len(s.BLSPublicKey)), uint64(len(s.Before)), uint64(len(s.After)), uint64(len(s.Request)), uint64(len(s.SealData)), uint64(len(s.Signature)), uint64(len(s.Seal)), uint64(len(s.Write)), uint64(len(s.Floor)), uint64(len(s.Ref.Namespace))} {
			var err error
			quota.Bytes, err = originAdd(quota.Bytes, n)
			if err != nil {
				return quota, err
			}
		}
	}
	return quota, b.signer(quota)
}

func originGroupMetadata(records []Record, span uint64, b *originBudget) (signerOriginGroup, error) {
	g := signerOriginGroup{records: records, span: span, reads: map[WALReadRef]originRead{}}
	// Validation includes canonical frame checksums and exact declaration equality.
	if err := b.pass(span, 16); err != nil {
		return g, err
	}
	var signerID, logID uint64
	sourceRefs := map[privval.SourceRef]bool{}
	for i, rec := range records {
		if err := b.work(1); err != nil {
			return g, err
		}
		switch r := rec.Body.(type) {
		case *SegmentRec:
			if r == nil {
				return g, originInconsistent("nil_segment")
			}
			if g.identity == nil {
				g.identity = &r.Identity
			} else if !reflect.DeepEqual(*g.identity, r.Identity) {
				return g, originInconsistent("origin_writer_identity_changed")
			}
		case *WALReadRec:
			if g.identity == nil || r == nil {
				return g, originInconsistent("origin_read_owner_missing")
			}
			if !validWALReadRec(r) {
				return g, originInconsistent("invalid_origin_read")
			}
			if r.Source.Unavailable != "" || r.Source.Error != "" {
				return g, &originLimitError{"origin_read_unavailable"}
			}
			if r.Source.Namespace != g.identity.Run {
				return g, originInconsistent("origin_read_owner_changed")
			}
			if logID != 0 && logID != r.Source.Log {
				return g, &originLimitError{"multiple_origin_reader_lifetimes_unsupported"}
			}
			logID = r.Source.Log
			ref := WALReadRef{r.Source.Namespace, r.Source.Log, r.Source.Sequence}
			if _, exists := g.reads[ref]; exists {
				return g, originInconsistent("origin_read_reused")
			}
			if err := b.work(1 + uint64(len(ref.Namespace))); err != nil {
				return g, err
			}
			g.reads[ref] = originRead{r, i}
		case *SignerRec:
			if g.identity == nil || r == nil {
				return g, originInconsistent("origin_signer_owner_missing")
			}
			s := &r.Source
			if s.Ref.Namespace != g.identity.Run {
				return g, originInconsistent("origin_signer_owner_changed")
			}
			if signerID != 0 && signerID != s.Ref.Signer {
				return g, &originLimitError{"multiple_origin_signer_lifetimes_unsupported"}
			}
			signerID = s.Ref.Signer
			if err := b.work(1 + uint64(len(s.Ref.Namespace))); err != nil {
				return g, err
			}
			if sourceRefs[s.Ref] {
				return g, originInconsistent("origin_signer_ref_reused")
			}
			sourceRefs[s.Ref] = true
			if g.first == nil || s.Ref.Sequence < g.first.Ref.Sequence {
				g.first = s
			}
			if g.last == nil || s.Ref.Sequence > g.last.Ref.Sequence {
				g.last = s
			}
		case *SignerCallRec:
			if r == nil {
				return g, originInconsistent("nil_signer_call")
			}
			g.calls = append(g.calls, originCall{r, i})
		case *CoreStepRec:
			if r == nil {
				return g, originInconsistent("nil_core_step")
			}
			g.replayed = g.replayed || r.ReplayedPrefix
		}
	}
	id := g.identity
	if id == nil || id.Run == "" || id.Self == (types.Address{}) || id.Self != id.Core.Self || id.ChainID == nil || id.ChainID.Sign() <= 0 || id.GenesisHash == (types.Hash{}) || len(id.Core.ChainConfig) == 0 {
		return g, &originLimitError{"origin_domain_missing"}
	}
	if id.Mode != "standalone" && id.Mode != "embedded" || id.Mode == "standalone" && id.WireOffset != 0x10 || id.Mode == "embedded" && id.WireOffset != 0 {
		return g, &originLimitError{"origin_wire_domain_unsupported"}
	}
	if g.first == nil || g.last == nil || len(g.first.BLSPublicKey) == 0 {
		return g, &originLimitError{"origin_signer_source_missing"}
	}
	if g.first.Address != id.Self || len(id.BLSPublicKey) > 0 && !bytes.Equal(id.BLSPublicKey, g.first.BLSPublicKey) {
		return g, originInconsistent("origin_declared_key_changed")
	}
	return g, nil
}

func originDomainEqual(a, b *Identity) bool {
	return a.Self == b.Self && a.ChainID.Cmp(b.ChainID) == 0 && a.GenesisHash == b.GenesisHash && a.Mode == b.Mode && a.WireOffset == b.WireOffset && a.ConfigDigest == b.ConfigDigest && reflect.DeepEqual(a.Core, b.Core)
}

func joinSignerOrigin(previous, current *signerOriginGroup, link SignerOriginLink, b *originBudget) (map[walOwnPosition]bool, error) {
	if err := b.pass(previous.span, 16); err != nil {
		return nil, err
	}
	if err := b.pass(current.span, 16); err != nil {
		return nil, err
	}
	if link.PreviousRead.Namespace != previous.identity.Run || link.CurrentRead.Namespace != current.identity.Run || link.PreviousSigner.Namespace != previous.identity.Run || link.CurrentSigner.Namespace != current.identity.Run {
		return nil, originInconsistent("origin_edge_owner_changed")
	}
	if !originDomainEqual(previous.identity, current.identity) {
		return nil, &originLimitError{"origin_domain_change_unsupported"}
	}
	if link.PreviousSigner != previous.last.Ref || link.CurrentSigner != current.first.Ref {
		return nil, &originLimitError{"origin_signer_endpoint_missing"}
	}
	before, after := previous.last, current.first
	if after.Action != "initial" || after.Ref.Sequence != 1 || after.Result != "ok" {
		return nil, originInconsistent("origin_initial_state_changed")
	}
	if before.Address != after.Address || !bytes.Equal(before.BLSPublicKey, after.BLSPublicKey) {
		return nil, &originLimitError{"origin_signer_key_change_unsupported"}
	}
	if !bytes.Equal(before.After, after.Before) || !bytes.Equal(after.Before, after.After) {
		return nil, &originLimitError{"origin_signer_state_handoff_missing"}
	}
	p, pok := previous.reads[link.PreviousRead]
	c, cok := current.reads[link.CurrentRead]
	if !pok || !cok {
		return nil, &originLimitError{"origin_exact_read_missing"}
	}
	pf, cf := p.record.Source.Frames, c.record.Source.Frames
	if err := originTake(&b.left.Frames, &b.usage.Frames, uint64(len(pf))+uint64(len(cf)), "origin_frame_limit"); err != nil {
		return nil, err
	}
	if len(pf) != len(cf) {
		return nil, &originLimitError{"origin_read_horizon_change_unsupported"}
	}
	bound := map[walOwnPosition]bool{}
	for i, f := range pf {
		other := cf[i]
		n, err := originAdd(uint64(len(f.Bytes)), uint64(len(other.Bytes)))
		if err != nil {
			return nil, err
		}
		if err = b.work(n); err != nil {
			return nil, err
		}
		if f.Position != other.Position || !bytes.Equal(f.Bytes, other.Bytes) {
			return nil, &originLimitError{"origin_read_horizon_change_unsupported"}
		}
		key := walOwnPosition{link.PreviousRead.Namespace, link.PreviousRead.Log, f.Position.Segment, uint64(f.Position.Offset)}
		if err := b.work(1 + uint64(len(key.namespace))); err != nil {
			return nil, err
		}
		if previous.proof.bound[key] {
			wire, ok := previous.proof.frames[key]
			if !ok || len(f.Bytes) < 10 || !bytes.Equal(wire, f.Bytes) {
				return nil, originInconsistent("origin_authenticated_frame_changed")
			}
			bound[walOwnPosition{link.CurrentRead.Namespace, link.CurrentRead.Log, f.Position.Segment, uint64(f.Position.Offset)}] = true
		}
	}
	// Every locally authenticated call must occur before this particular retained
	// read. Another later read is never silently substituted for the explicit ref.
	for _, entry := range previous.calls {
		call := entry.record
		if entry.index >= p.index || call.WAL.Namespace != link.PreviousRead.Namespace || call.WAL.Log != link.PreviousRead.Log || call.WAL.Sequence >= link.PreviousRead.Sequence {
			return nil, &originLimitError{"origin_read_not_after_original_call"}
		}
		key := walOwnPosition{link.PreviousRead.Namespace, link.PreviousRead.Log, call.Segment, call.Offset}
		if !previous.proof.bound[key] || !bound[walOwnPosition{link.CurrentRead.Namespace, link.CurrentRead.Log, call.Segment, call.Offset}] {
			return nil, &originLimitError{"origin_original_call_outside_horizon"}
		}
	}
	for key, read := range current.proof.needs {
		if err := b.work(1 + uint64(len(key.namespace))); err != nil {
			return nil, err
		}
		if read != link.CurrentRead {
			return nil, &originLimitError{"multiple_origin_restore_reads_unsupported"}
		}
		if !bound[key] && !current.proof.bound[key] {
			return nil, &originLimitError{"origin_own_binding_missing"}
		}
	}
	return bound, nil
}

func emptySignerOrigins(origins *SignerOriginSources) bool {
	return origins == nil || len(origins.Prior) == 0 && len(origins.Links) == 0
}

// CheckRestoredSignerSourcesWithOrigins independently authenticates one ordered
// chain of original signing/WAL observations. Success is conditional on explicit
// logical handoff witnesses; it does not establish physical history or custody.
func CheckRestoredSignerSourcesWithOrigins(records []Record, coreLimits CoreSourceLimits, signerLimits privval.SourceLimits, origins *SignerOriginSources, limits SignerOriginLimits) (RestoreCheck, CoreSourceCheck, RestoreEffectsCheck, RestoredSignerOriginCheck, error) {
	if emptySignerOrigins(origins) {
		r, c, e, s, err := CheckRestoredSignerSources(records, coreLimits, signerLimits)
		return r, c, e, RestoredSignerOriginCheck{Status: s.Status, Reason: s.Reason, Scope: s.Scope, PhysicalStatus: s.PhysicalStatus, OriginStatus: "not_requested", Current: s, CurrentInspected: true}, err
	}
	b, err := newOriginBudget(limits)
	if err != nil {
		return RestoreCheck{}, CoreSourceCheck{}, RestoreEffectsCheck{}, RestoredSignerOriginCheck{Status: "unavailable", Reason: err.Error(), OriginStatus: "unavailable", PhysicalStatus: "unavailable"}, nil
	}
	return inspectSignerOrigins(records, coreLimits, signerLimits, origins, b)
}

func inspectSignerOrigins(records []Record, coreLimits CoreSourceLimits, signerLimits privval.SourceLimits, origins *SignerOriginSources, b *originBudget) (restore RestoreCheck, core CoreSourceCheck, effects RestoreEffectsCheck, report RestoredSignerOriginCheck, err error) {
	report = RestoredSignerOriginCheck{Status: "unavailable", Scope: "restored_signer_sources_on_explicit_origin_witness", PhysicalStatus: "unavailable", OriginStatus: "unavailable", OriginScope: "ordered_original_signing_state_and_full_read_handoffs"}
	defer func() { report.Usage = b.usage }()
	fail := func(e error) (RestoreCheck, CoreSourceCheck, RestoreEffectsCheck, RestoredSignerOriginCheck, error) {
		report.Reason = e.Error()
		if errorsIsOrigin(e) {
			report.Status, report.OriginStatus = "inconsistent", "inconsistent"
		}
		var limit *originLimitError
		if errors.As(e, &limit) {
			return restore, core, effects, report, nil
		}
		return restore, core, effects, report, e
	}
	n := uint64(len(origins.Prior))
	if n == 0 || len(origins.Links) != len(origins.Prior) {
		return fail(originInconsistent("origin_chain_shape"))
	}
	writers, overflow := originAdd(n, 1)
	if overflow != nil {
		return fail(overflow)
	}
	if e := originTake(&b.left.Writers, &b.usage.Writers, writers, "origin_writer_limit"); e != nil {
		return fail(e)
	}
	if e := originTake(&b.left.Links, &b.usage.Links, n, "origin_link_limit"); e != nil {
		return fail(e)
	}
	if _, e := b.shape(origins.Links); e != nil {
		return fail(e)
	}
	groups := make([]signerOriginGroup, 0, len(origins.Prior)+1)
	owners := map[string]bool{}
	for i := 0; i <= len(origins.Prior); i++ {
		input := records
		if i < len(origins.Prior) {
			input = origins.Prior[i].Records
		}
		shape, e := b.shape(input)
		if e != nil {
			return fail(e)
		}
		// Count all supplied original frames before any canonical decoder runs.
		for _, row := range input {
			if read, ok := row.Body.(*WALReadRec); ok && read != nil {
				if e = originTake(&b.left.Frames, &b.usage.Frames, uint64(len(read.Source.Frames)), "origin_frame_limit"); e != nil {
					return fail(e)
				}
			}
		}
		groups = append(groups, signerOriginGroup{records: input, span: shape.span})
	}
	for i := range groups {
		g, e := originGroupMetadata(groups[i].records, groups[i].span, b)
		if e != nil {
			return fail(e)
		}
		if owners[g.identity.Run] {
			return fail(originInconsistent("origin_cycle_or_writer_reused"))
		}
		owners[g.identity.Run] = true
		groups[i] = g
	}
	for i := range groups {
		g := &groups[i]
		isCurrent := i == len(groups)-1
		if g.replayed || isCurrent {
			r, c, e, x := checkRestoredBoundarySourcesBudget(g.records, coreLimits, b, g.span)
			if isCurrent {
				restore, core, effects = r, c, e
			}
			if x != nil || r.Status != "consistent" || c.Status != "consistent" || e.Status != "consistent" {
				if b.failure != nil {
					return fail(b.failure)
				}
				if isCurrent {
					report.Current = RestoreSignerCheck{Status: "unavailable", Reason: "restore_boundary_not_reconstructed", Scope: "restored_boundary_signer_state_and_own_wal", PhysicalStatus: "unavailable"}
					report.CurrentInspected = true
				}
				if x != nil {
					return fail(x)
				}
				return fail(&originLimitError{"origin_restore_boundary_not_reconstructed"})
			}
		}
		captured := false
		signing, x := inspectRestoreSignerCalls(g.records, coreLimits, signerLimits, b, g.span, func(proof signerOriginEvidence) { g.proof = proof; captured = true })
		if b.failure != nil {
			return fail(b.failure)
		}
		if isCurrent {
			report.Current = signing
			report.CurrentInspected = true
		}
		if x != nil {
			return fail(x)
		}
		if g.proof.unsupported != "" {
			return fail(&originLimitError{g.proof.unsupported})
		}
		if !captured {
			return fail(&originLimitError{"origin_signer_" + signing.Reason})
		}
		if i > 0 {
			inherited, x := joinSignerOrigin(&groups[i-1], g, origins.Links[i-1], b)
			if x != nil {
				return fail(x)
			}
			for key := range inherited {
				if err := b.work(1 + uint64(len(key.namespace))); err != nil {
					return fail(err)
				}
				if g.proof.bound[key] {
					return fail(originInconsistent("ambiguous_origin_own_binding"))
				}
				g.proof.bound[key] = true
				previousKey := walOwnPosition{origins.Links[i-1].PreviousRead.Namespace, origins.Links[i-1].PreviousRead.Log, key.segment, key.offset}
				g.proof.frames[key] = groups[i-1].proof.frames[previousKey]
			}
			if isCurrent {
				for key := range g.proof.needs {
					if inherited[key] {
						report.InheritedOwnBindings++
					}
				}
			}
			report.Links++
		}
		for key := range g.proof.needs {
			if err := b.work(1 + uint64(len(key.namespace))); err != nil {
				return fail(err)
			}
			if !g.proof.bound[key] {
				return fail(&originLimitError{"origin_predecessor_own_binding_missing"})
			}
		}
		if len(g.proof.bound) == 0 {
			return fail(&originLimitError{"origin_no_authenticated_own_bindings"})
		}
		if !isCurrent {
			report.PriorRuns++
		}
	}
	report.Status, report.OriginStatus = "consistent_on_explicit_origin_witness", "consistent_on_explicit_origin_witness"
	return restore, core, effects, report, nil
}
