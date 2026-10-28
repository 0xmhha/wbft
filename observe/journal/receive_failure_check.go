package journal

import (
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// ReceiveFailureLimits bound finite transcript inspection, not runtime memory,
// verification CPU, socket arrivals, or functional replay.
type ReceiveFailureLimits struct {
	Inbox  InboxLimits
	Caches uint64
}

type ReceiveFailureCheck struct {
	Status           string     `json:"status"`
	Reason           string     `json:"reason,omitempty"`
	Scope            string     `json:"scope"`
	PhysicalStatus   string     `json:"physical_status"`
	ScheduleStatus   string     `json:"schedule_status"`
	Caches           uint64     `json:"caches,string"`
	Operations       uint64     `json:"operations,string"`
	VerifiedFailures uint64     `json:"verified_failures,string"`
	Stored           uint64     `json:"stored,string"`
	LookupHits       uint64     `json:"lookup_hits,string"`
	ConsumedFailures uint64     `json:"consumed_failures,string"`
	Retained         uint64     `json:"retained,string"`
	Inbox            InboxCheck `json:"inbox"`
}

var ErrReceiveFailureSource = errors.New("journal: inconsistent receive failure source")

type failureCacheKey struct {
	run   string
	cache uint64
}

type failureRequestKey struct {
	run     string
	request uint64
}

type failurePayloadKey struct {
	code uint64
	hash types.Hash
}

type failureRetained struct {
	class  transport.ReceiveFailureClass
	ref    transport.ReceiveFailureRef
	source transport.ReceiveFailureSource
}

type failureDeclaration struct {
	failure  ReceiveFailureCacheOptions
	accepted CachePolicyOptions
}

type failureObservedHit struct {
	hit *InboxFailureHitRec
	run string
}

func failurePublicationEqual(a, b transport.ReceiveFailureSource) bool {
	a.WorkerRequest, b.WorkerRequest = 0, 0
	return a == b
}

func failureInboxSourceEqual(r *InboxRec, s transport.ReceiveFailureSource) bool {
	phase := ""
	switch s.SnapshotPhase {
	case transport.ReceiveFailureStart:
		phase = "start"
	case transport.ReceiveFailureStep:
		phase = "step"
	case transport.ReceiveFailureReplay:
		phase = "replay"
	}
	return r.SnapshotEngine == s.EngineRun && r.SnapshotStep == s.SnapshotStep && r.SnapshotPhase == phase && r.SnapshotContextHash == s.SnapshotHash
}

// CheckReceiveFailureSources independently executes original core sources,
// rechecks original failed inputs, reconstructs the bounded cache in its mutex
// order, and certifies separate hit consumption in the original inbox model.
// A hit is never injected as an executed check, signer, or core input. Ordinary
// source APIs and functional replay keep their unsupported-profile guards.
func CheckReceiveFailureSources(records []Record, limits ReceiveFailureLimits) (ReceiveFailureCheck, error) {
	report := ReceiveFailureCheck{Status: "unavailable", Scope: "original_failure_checks_bounded_cache_and_inbox_consumption", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (ReceiveFailureCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (ReceiveFailureCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrReceiveFailureSource, reason)
	}
	if limits.Caches == 0 || limits.Inbox.Operations == 0 || limits.Inbox.Entries == 0 || limits.Inbox.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	if limits.Inbox.Core.Records == 0 || uint64(len(records)) > limits.Inbox.Core.Records {
		return unavailable("record_limit")
	}
	declarations := map[string]failureDeclaration{}
	groups := map[failureCacheKey][]*ReceiveFailureCacheRec{}
	appends, checks, dequeues := map[failureRequestKey]*InboxRec{}, map[failureRequestKey]*InboxRec{}, map[failureRequestKey]*InboxRec{}
	var hits []failureObservedHit
	seenHits := map[*InboxFailureHitRec]bool{}
	writer := ""
	var span, operations uint64
	for _, record := range records {
		if _, ok := record.Body.(*ReceiveFailureCacheRec); ok {
			operations++
		}
		if _, ok := record.Body.(*InboxFailureHitRec); ok {
			operations++
		}
		if _, ok := record.Body.(*InboxRec); ok {
			operations++
		}
		if operations > limits.Inbox.Operations {
			return unavailable("operation_limit")
		}
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
			if writer == "" {
				return unavailable("writer_missing")
			}
			if r.Core.ReceiveFailureCache == nil || r.Core.validateReceiveFailureHeader() != nil {
				return unavailable("receive_failure_declaration_missing_or_unsupported")
			}
			declaration := failureDeclaration{*r.Core.ReceiveFailureCache, *r.Core.CachePolicy}
			if old, exists := declarations[writer]; exists && old != declaration {
				return inconsistent("writer_failure_declaration_changed")
			}
			if _, exists := declarations[writer]; !exists && uint64(len(declarations)) >= limits.Inbox.Core.Runs {
				return unavailable("writer_limit")
			}
			declarations[writer] = declaration
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, kind := range r.ByKind {
				if kind.Count > 0 && (kind.Kind == 0 || kind.Kind == uint64(KindReceiveFailure) || kind.Kind == uint64(KindInboxFailureHit)) {
					return unavailable("receive_failure_source_gap")
				}
			}
		case *ReceiveFailureCacheRec:
			if writer == "" || r.Transition.Run == "" {
				return unavailable("failure_namespace_missing")
			}
			if r.Transition.Run != writer {
				return inconsistent("failure_writer_changed")
			}
			if r.Version != ReceiveFailureRecordVersion {
				return unavailable("failure_record_version")
			}
			if r.Mono < 0 || r.WallNs < 0 || !validReceiveFailureEvent(r.Transition) {
				return inconsistent("invalid_failure_cache_source")
			}
			if r.Transition.Unavailable != "" {
				return unavailable("failure_" + r.Transition.Unavailable)
			}
			declaration, known := declarations[writer]
			if !known || declaration.failure.Entries != r.Transition.Capacity {
				return inconsistent("failure_capacity_differs_from_declaration")
			}
			if r.Transition.Capacity > limits.Inbox.Entries {
				return unavailable("entry_limit")
			}
			key := failureCacheKey{writer, r.Transition.Cache}
			if _, exists := groups[key]; !exists && uint64(len(groups)) >= limits.Caches {
				return unavailable("cache_limit")
			}
			groups[key] = append(groups[key], r)
		case *InboxRec:
			if writer == "" {
				return unavailable("inbox_writer_missing")
			}
			key := failureRequestKey{writer, r.Request}
			var index map[failureRequestKey]*InboxRec
			switch r.Action {
			case "append":
				index = appends
			case "check":
				index = checks
			case "dequeue":
				index = dequeues
			}
			if index != nil {
				if index[key] != nil {
					return inconsistent("failure_inbox_request_repeated")
				}
				index[key] = r
			}
		case *InboxFailureHitRec:
			if writer == "" || r.Unavailable != "" || r.Source.Unavailable != "" {
				return unavailable("inbox_failure_source_missing")
			}
			if !validInboxFailureHit(r) {
				return inconsistent("invalid_inbox_failure_hit")
			}
			if seenHits[r] {
				return inconsistent("inbox_failure_hit_repeated")
			}
			seenHits[r] = true
			hits = append(hits, failureObservedHit{r, writer})
		}
		// Bound all detached cache/inbox spans retained by this inspection.
		switch record.Body.(type) {
		case *ReceiveFailureCacheRec, *InboxFailureHitRec, *InboxRec:
			n := uint64(size(record))
			if n > limits.Inbox.Bytes-span {
				return unavailable("byte_limit")
			}
			span += n
		}
	}
	if len(groups) == 0 {
		return unavailable("no_receive_failure_cache_sources")
	}
	publications := map[appCoreKey]inboxSourceSnapshot{}
	core, _, err := inspectCoreSourceProfile(records, limits.Inbox.Core, nil, func(writer string, source *CoreStepRec, snapshot *consensus.Snapshot) {
		publications[appCoreKey{writer, source.EngineRun, source.Step}] = inboxSourceSnapshot{source, snapshot}
	}, nil, true)
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	publication := func(run string, source transport.ReceiveFailureSource, mono int64) (*consensus.Snapshot, string, bool) {
		if source.SnapshotPhase == transport.ReceiveFailureReplay {
			return nil, "receive_failure_restore_profile_unavailable", false
		}
		p, exists := publications[appCoreKey{run, source.EngineRun, source.SnapshotStep}]
		if !exists {
			return nil, "failure_publication_missing", false
		}
		if p.source.Entry.Mono > mono {
			return nil, "failure_publication_from_future", true
		}
		phase := transport.ReceiveFailureStep
		if p.source.InputKind == inputlog.KindStart {
			phase = transport.ReceiveFailureStart
		}
		digest, e := InboxSnapshotDigest(p.snapshot)
		if e != nil {
			return nil, "snapshot_encoding", false
		}
		if !p.snapshot.Running || source.SnapshotPhase != phase || source.SnapshotHash != digest {
			return nil, "failure_publication_changed", true
		}
		return p.snapshot, "", false
	}
	workerSource := func(run string, source transport.ReceiveFailureSource, code uint64, hash types.Hash, mono int64) (*InboxRec, *consensus.Snapshot, string, bool) {
		original := appends[failureRequestKey{run, source.WorkerRequest}]
		dequeue := dequeues[failureRequestKey{run, source.WorkerRequest}]
		if original == nil || dequeue == nil {
			return nil, nil, "failure_worker_input_missing", false
		}
		if original.Code != code || codec.DedupKey(original.Payload) != hash || !sameInboxIdentity(original, dequeue) {
			return nil, nil, "failure_worker_input_changed", true
		}
		if dequeue.Mono > uint64(mono) {
			return nil, nil, "failure_dequeue_from_future", true
		}
		snapshot, reason, invalid := publication(run, source, mono)
		return original, snapshot, reason, invalid
	}
	keys := make([]failureCacheKey, 0, len(groups))
	for key := range groups { //wbft:unordered sorted before inspection
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b failureCacheKey) int {
		if a.run < b.run || a.run == b.run && a.cache < b.cache {
			return -1
		}
		if a == b {
			return 0
		}
		return 1
	})
	lookups := map[transport.ReceiveFailureRef]*ReceiveFailureCacheRec{}
	requests := map[failureRequestKey]*ReceiveFailureCacheRec{}
	usedChecks := map[failureRequestKey]bool{}
	for _, key := range keys {
		items := groups[key]
		slices.SortFunc(items, func(a, b *ReceiveFailureCacheRec) int {
			if a.Transition.Sequence < b.Transition.Sequence {
				return -1
			}
			if a.Transition.Sequence > b.Transition.Sequence {
				return 1
			}
			return 0
		})
		entries := map[failurePayloadKey]failureRetained{}
		var order []failurePayloadKey
		var sequence, context uint64
		var contextSource transport.ReceiveFailureSource
		closed := false
		for _, record := range items {
			e := record.Transition
			if e.Sequence == sequence {
				return inconsistent("failure_sequence_repeated")
			}
			if e.Sequence != sequence+1 {
				return unavailable("failure_sequence_gap")
			}
			sequence = e.Sequence
			if e.Before != uint64(len(order)) || e.Closed != (closed || e.Action == "close") {
				return inconsistent("failure_lifetime_or_count_changed")
			}
			payloadKey := failurePayloadKey{e.Code, e.Payload}
			switch e.Action {
			case "context":
				entries, order = map[failurePayloadKey]failureRetained{}, nil
				old := context
				context = 0
				if e.Active {
					if closed || e.Source.WorkerRequest != 0 || e.Context != e.Sequence {
						return inconsistent("failure_context_changed")
					}
					if _, reason, invalid := publication(key.run, e.Source, int64(record.Mono)); reason != "" {
						if invalid {
							return inconsistent(reason)
						}
						return unavailable(reason)
					}
					context, contextSource = e.Context, e.Source
				} else if e.Context != old {
					return inconsistent("inactive_failure_context_changed")
				}
			case "invalidate", "close":
				if e.Context != context {
					return inconsistent("failure_invalidation_context_changed")
				}
				entries, order, context = map[failurePayloadKey]failureRetained{}, nil, 0
				closed = closed || e.Action == "close"
			case "lookup", "record":
				if e.Context != context || e.Active && (closed || context == 0 || e.RequestedRun != key.run || e.RequestedCache != key.cache || e.RequestedContext != context || !failurePublicationEqual(e.Source, contextSource)) {
					return inconsistent("failure_operation_context_changed")
				}
				original, snapshot, reason, invalid := workerSource(key.run, e.Source, e.Code, e.Payload, int64(record.Mono))
				if reason != "" {
					if invalid {
						return inconsistent(reason)
					}
					return unavailable(reason)
				}
				requestKey := failureRequestKey{key.run, e.Source.WorkerRequest}
				ref := transport.ReceiveFailureRef{Run: key.run, Cache: key.cache, Sequence: e.Sequence}
				retained, exists := entries[payloadKey]
				if e.Action == "lookup" {
					if requests[requestKey] != nil {
						return inconsistent("worker_failure_lookup_repeated")
					}
					requests[requestKey], lookups[ref] = record, record
					if e.Hit != (e.Active && exists) {
						return inconsistent("failure_lookup_changed")
					}
					if e.Hit {
						if e.Class != retained.class || e.Reference != retained.ref || e.Original != retained.source {
							return inconsistent("failure_original_reference_changed")
						}
						report.LookupHits++
					}
				} else {
					check := checks[requestKey]
					lookup := requests[requestKey]
					if check == nil || lookup == nil {
						return unavailable("original_failure_check_missing")
					}
					l := lookup.Transition
					if usedChecks[requestKey] || l.Hit || l.Sequence >= e.Sequence || l.Source != e.Source || l.Code != e.Code || l.Payload != e.Payload || l.RequestedRun != e.RequestedRun || l.RequestedCache != e.RequestedCache || l.RequestedContext != e.RequestedContext || !failureInboxSourceEqual(check, e.Source) || !sameInboxIdentity(original, check) {
						return inconsistent("original_failure_check_changed")
					}
					if uint64(record.Mono) > check.Mono {
						return inconsistent("failure_check_before_registration_callback")
					}
					member := func(a types.Address, _ types.View) bool {
						return snapshot.Validators != nil && snapshot.Validators.Contains(a) || snapshot.PriorValidators != nil && snapshot.PriorValidators.Contains(a)
					}
					_, failure, recoverError := consensus.RecoverWithFailure(codec.Code(original.Code), original.Payload, member)
					class, result := transport.ReceiveFailureClass(0), ""
					switch failure {
					case consensus.RecoverySignature:
						class, result = transport.ReceiveSignatureFailure, "signature"
					case consensus.RecoveryMembership:
						class, result = transport.ReceiveMembershipFailure, "membership"
					}
					if recoverError == nil || class == 0 || e.Class != class || check.Result != result {
						return inconsistent("original_typed_failure_changed")
					}
					usedChecks[requestKey] = true
					report.VerifiedFailures++
					if e.Stored != (e.Active && !exists) {
						return inconsistent("failure_registration_changed")
					}
					if !e.Active && (e.Reference != (transport.ReceiveFailureRef{}) || e.Original != (transport.ReceiveFailureSource{})) {
						return inconsistent("inactive_failure_registration_reference")
					}
					if e.Stored {
						if e.Reference != ref {
							return inconsistent("failure_registration_reference_changed")
						}
						if uint64(len(order)) == e.Capacity {
							delete(entries, order[0])
							order = order[1:]
						}
						entries[payloadKey] = failureRetained{class, ref, e.Source}
						order = append(order, payloadKey)
						report.Stored++
					} else if e.Active && (e.Reference != retained.ref || e.Class != retained.class || e.Original != retained.source) {
						return inconsistent("failure_duplicate_registration_changed")
					}
				}
				// Both lookup hits and duplicate registrations use the original
				// cache Get, which moves that key to the newest LRU position.
				if e.Active && exists {
					index := slices.Index(order, payloadKey)
					order = append(slices.Delete(order, index, index+1), payloadKey)
				}
			}
			if e.After != uint64(len(order)) {
				return inconsistent("failure_retained_count_changed")
			}
			report.Operations++
		}
		report.Caches++
		report.Retained += uint64(len(order))
	}
	certified, consumed := failureInboxEvidenceSet{}, map[failureRequestKey]bool{}
	slices.SortFunc(hits, func(a, b failureObservedHit) int {
		if a.run < b.run || a.run == b.run && a.hit.Source.Sequence < b.hit.Source.Sequence {
			return -1
		}
		if a.run == b.run && a.hit.Source.Sequence == b.hit.Source.Sequence {
			return 0
		}
		return 1
	})
	for _, observed := range hits {
		hit, run := observed.hit, observed.run
		source := &hit.Source
		key := failureRequestKey{run, source.Request}
		lookup := lookups[hit.Lookup]
		if lookup == nil {
			return unavailable("failure_lookup_source_missing")
		}
		e := lookup.Transition
		if consumed[key] || checks[key] != nil || hit.Lookup.Run != run || !e.Hit || e.Source.WorkerRequest != source.Request || e.Code != source.Code || e.Class != hit.Class || e.Reference != hit.Original || !failureInboxSourceEqual(source, e.Source) {
			return inconsistent("inbox_failure_consumption_changed")
		}
		if uint64(lookup.Mono) > source.Mono {
			return inconsistent("failure_hit_before_lookup_callback")
		}
		original := appends[key]
		if original == nil || dequeues[key] == nil {
			return unavailable("inbox_failure_input_missing")
		}
		if !sameInboxIdentity(original, source) || codec.DedupKey(original.Payload) != e.Payload {
			return inconsistent("inbox_failure_input_changed")
		}
		certified[source], consumed[key] = true, true
		report.ConsumedFailures++
	}
	report.Inbox, err = inspectInboxSourcesProfile(records, limits.Inbox, nil, false, certified)
	if err != nil {
		return inconsistent("inbox_" + report.Inbox.Reason)
	}
	if report.Inbox.Status != "consistent" {
		return unavailable("inbox_" + report.Inbox.Reason)
	}
	if report.Inbox.CachedFailures != report.ConsumedFailures {
		return inconsistent("inbox_failure_count_changed")
	}
	report.Status = "consistent"
	return report, nil
}
