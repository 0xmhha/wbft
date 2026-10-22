package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// ReceiveCacheRec observes actual checking-ledger operations, independently
// from legacy read-loop CacheRec. Coordinates and hashes require independent
// core/capture checks; decoding this record does not enable runtime replay.
type ReceiveCacheRec struct {
	Transition transport.ReceiveTransition
	Mono       time.Duration
	WallNs     int64
}

type validationContextRLP struct {
	Sequence, Round, State, PriorRound        string
	Validators, PriorValidators               types.Hash
	ValidatorsPresent, PriorValidatorsPresent uint64
}

func receiveContextWire(context transport.ValidationContext) validationContextRLP {
	return validationContextRLP{Sequence: context.Sequence, Round: context.Round, State: context.State, PriorRound: context.PriorRound, Validators: context.Validators, PriorValidators: context.PriorValidators, ValidatorsPresent: boolUint(context.ValidatorsPresent), PriorValidatorsPresent: boolUint(context.PriorValidatorsPresent)}
}
func receiveContextValue(context validationContextRLP) transport.ValidationContext {
	return transport.ValidationContext{Sequence: context.Sequence, Round: context.Round, State: context.State, PriorRound: context.PriorRound, Validators: context.Validators, PriorValidators: context.PriorValidators, ValidatorsPresent: context.ValidatorsPresent == 1, PriorValidatorsPresent: context.PriorValidatorsPresent == 1}
}
func canonicalContextNumber(text string) bool {
	if text == "" || len(text) > 1 && text[0] == '0' {
		return false
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validValidationContext(context transport.ValidationContext) bool {
	if !canonicalContextNumber(context.Sequence) || !canonicalContextNumber(context.Round) || !canonicalContextNumber(context.PriorRound) {
		return false
	}
	switch context.State {
	case "AcceptRequest", "Preprepared", "Prepared", "Committed":
	default:
		return false
	}
	return (context.ValidatorsPresent || context.Validators == (types.Hash{})) && (context.PriorValidatorsPresent || context.PriorValidators == (types.Hash{}))
}

type receiveCacheRLP struct {
	Format, JSeq, Ledger, Sequence, Action, Request, Scope uint64
	Input, Checked                                         transport.WriteIdentity
	Origin, CheckedOrigin                                  transport.ReceiveOrigin
	Source                                                 transport.ReceiveAcceptSource
	Context                                                validationContextRLP
	Decision, Flags, PendingBefore, PendingAfter           uint64
	Pruned                                                 []uint64
	PendingLimit, PerPeerLimit, Mono, WallNs               uint64
}

func validReceiveOrigin(origin transport.ReceiveOrigin) bool {
	return (origin.WriterRun == "") == (origin.CaptureID == 0)
}
func validAcceptSource(source transport.ReceiveAcceptSource) bool {
	return source == (transport.ReceiveAcceptSource{}) || source.EngineRun > 0 && source.Step > 0 && source.Output > 0 && (source.Via == "direct" || source.Via == "self")
}
func receiveInputPresent(in transport.WriteIdentity) bool {
	return in.Key != (types.Hash{}) && in.PayloadSHA256 != (types.Hash{})
}

func validReceiveTransition(t transport.ReceiveTransition) bool {
	if !validSessionObservation(t.Input) || !validSessionObservation(t.Checked) {
		return false
	}
	if t.Ledger == 0 || t.Sequence == 0 || t.Action < transport.ReceiveLedgerStart || t.Action > transport.ReceiveLedgerClose || !validReceiveOrigin(t.Origin) || !validReceiveOrigin(t.CheckedOrigin) {
		return false
	}
	if t.ContextKnown {
		if t.Scope == 0 || !validValidationContext(t.Context) {
			return false
		}
	} else if t.Context != (transport.ValidationContext{}) {
		return false
	}
	zero := transport.WriteIdentity{}
	accept := t.Action == transport.ReceiveCheckAccept
	prepare := t.Action == transport.ReceiveCheckPrepare
	cancel := t.Action == transport.ReceiveCheckCancel
	lookup := t.Action == transport.ReceiveKnownInspect || t.Action == transport.ReceiveRecentInspect
	if !accept && !prepare && t.Decision != 0 {
		return false
	}
	if !accept && (t.Checked != zero || t.CheckedOrigin != (transport.ReceiveOrigin{}) || t.Source != (transport.ReceiveAcceptSource{}) || t.Matched) {
		return false
	}
	if !accept && !cancel && (t.Owned || t.Released) {
		return false
	}
	if !accept && !prepare && t.Action != transport.ReceiveKnownInspect && t.Known {
		return false
	}
	if !accept && t.Action != transport.ReceiveRecentInspect && t.Recent {
		return false
	}
	if !prepare && t.Action != transport.ReceivePendingPrune && len(t.Pruned) != 0 {
		return false
	}
	if !prepare && !accept && !cancel && t.Request != 0 {
		return false
	}
	if !prepare && !accept && !cancel && !lookup && (t.Scope != 0 || t.ScopeActive || t.Input != zero) {
		return false
	}
	if !prepare && !accept && !cancel && t.Origin != (transport.ReceiveOrigin{}) {
		return false
	}
	if t.Action != transport.ReceiveLedgerStart && (t.Sequence == 1 || t.PendingLimit != 0 || t.PerPeerLimit != 0 || t.KeyWithCode) {
		return false
	}
	if t.ScopeActive && t.Scope == 0 {
		return false
	}
	pruned := uint64(len(t.Pruned))
	if pruned > t.PendingBefore {
		return false
	}
	seen := make(map[uint64]bool, len(t.Pruned))
	for _, request := range t.Pruned {
		if request == 0 || request >= t.Sequence || seen[request] {
			return false
		}
		seen[request] = true
	}
	afterPrune := t.PendingBefore - pruned
	switch t.Action {
	case transport.ReceiveLedgerStart:
		return t.Sequence == 1 && t.PendingLimit > 0 && t.PerPeerLimit > 0 && t.PerPeerLimit <= t.PendingLimit && t.PendingBefore == 0 && t.PendingAfter == 0 && !t.Closed
	case transport.ReceiveCheckPrepare:
		if !receiveInputPresent(t.Input) {
			return false
		}
		if !t.ScopeActive || t.Closed {
			return t.Decision == transport.ReceiveUnavailable && t.Request == 0 && !t.Known && pruned == 0 && t.PendingAfter == t.PendingBefore
		}
		switch t.Decision {
		case transport.ReceiveReserved:
			return !t.Known && t.Request == t.Sequence && afterPrune != ^uint64(0) && t.PendingAfter == afterPrune+1
		case transport.ReceiveKnown:
			return t.Known && t.Request == 0 && t.PendingAfter == afterPrune
		case transport.ReceivePendingFull:
			return !t.Known && t.Request == 0 && t.PendingAfter == afterPrune
		}
		return false
	case transport.ReceiveCheckAccept, transport.ReceiveCheckCancel:
		if t.Request == 0 {
			if t.Scope != 0 || t.ScopeActive || t.Input != zero || t.Origin != (transport.ReceiveOrigin{}) || t.Owned {
				return false
			}
		} else if t.Request >= t.Sequence || t.Scope == 0 || !receiveInputPresent(t.Input) {
			return false
		}
		if cancel {
			if t.Released != t.Owned {
				return false
			}
		} else {
			if !receiveInputPresent(t.Checked) || !validAcceptSource(t.Source) {
				return false
			}
			matched := t.Owned && t.Input.Peer == t.Checked.Peer && t.Input.Code == t.Checked.Code && t.Input.Key == t.Checked.Key && t.Input.PayloadSHA256 == t.Checked.PayloadSHA256
			if t.Matched != matched || t.Released != matched {
				return false
			}
			if !matched {
				if t.Decision != transport.ReceiveUnavailable || t.Known || t.Recent {
					return false
				}
			} else if t.Closed || !t.ScopeActive {
				if t.Decision != transport.ReceiveExpired || t.Known || t.Recent {
					return false
				}
			} else if !t.Recent || t.Known && t.Decision != transport.ReceiveDuplicate || !t.Known && t.Decision != transport.ReceiveRegistered {
				return false
			}
		}
		if t.Released {
			return t.PendingBefore > 0 && t.PendingAfter == t.PendingBefore-1
		}
		return t.PendingAfter == t.PendingBefore
	case transport.ReceiveKnownInspect, transport.ReceiveRecentInspect:
		if !receiveInputPresent(t.Input) || t.Input.Session != 0 || !t.ScopeActive && (t.Known || t.Recent) {
			return false
		}
		if t.Action == transport.ReceiveKnownInspect && t.Input.Peer != (types.Address{}) {
			return false
		}
		return t.PendingAfter == t.PendingBefore
	case transport.ReceivePendingPrune:
		return t.PendingAfter == afterPrune
	case transport.ReceiveLedgerClose:
		return t.Closed && t.PendingAfter == 0
	}
	return false
}

func receiveFlags(t transport.ReceiveTransition) uint64 {
	var flags uint64
	for index, value := range []bool{t.Owned, t.Matched, t.ScopeActive, t.Closed, t.Known, t.Recent, t.Released, t.KeyWithCode, t.ContextKnown} {
		if value {
			flags |= 1 << index
		}
	}
	return flags
}
func encodeReceiveCacheRec(r *ReceiveCacheRec, jseq uint64) ([]byte, error) {
	t := r.Transition
	if r.Mono < 0 || !validReceiveTransition(t) {
		return nil, fmt.Errorf("journal: invalid accepted-receive cache observation")
	}
	return rlp.Encode(&receiveCacheRLP{Format: Format, JSeq: jseq, Ledger: t.Ledger, Sequence: t.Sequence, Action: uint64(t.Action), Request: t.Request, Scope: t.Scope, Input: t.Input, Checked: t.Checked, Origin: t.Origin, CheckedOrigin: t.CheckedOrigin, Source: t.Source, Context: receiveContextWire(t.Context), Decision: uint64(t.Decision), Flags: receiveFlags(t), PendingBefore: t.PendingBefore, PendingAfter: t.PendingAfter, Pruned: t.Pruned, PendingLimit: t.PendingLimit, PerPeerLimit: t.PerPeerLimit, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}
func decodeReceiveCacheRec(body []byte) (Record, error) {
	var w receiveCacheRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: accepted-receive cache: %v", ErrRecord, err)
	}
	if w.Format != Format || w.Action > 255 || w.Decision > 255 || w.Flags > 511 || w.Context.ValidatorsPresent > 1 || w.Context.PriorValidatorsPresent > 1 {
		return Record{}, fmt.Errorf("%w: invalid accepted-receive cache encoding", ErrRecord)
	}
	t := transport.ReceiveTransition{Ledger: w.Ledger, Sequence: w.Sequence, Action: transport.ReceiveAction(w.Action), Request: w.Request, Scope: w.Scope, Input: w.Input, Checked: w.Checked, Origin: w.Origin, CheckedOrigin: w.CheckedOrigin, Source: w.Source, Context: receiveContextValue(w.Context), ContextKnown: w.Flags&256 != 0, Decision: transport.ReceiveDecision(w.Decision), Owned: w.Flags&1 != 0, Matched: w.Flags&2 != 0, ScopeActive: w.Flags&4 != 0, Closed: w.Flags&8 != 0, Known: w.Flags&16 != 0, Recent: w.Flags&32 != 0, Released: w.Flags&64 != 0, KeyWithCode: w.Flags&128 != 0, PendingBefore: w.PendingBefore, PendingAfter: w.PendingAfter, Pruned: w.Pruned, PendingLimit: w.PendingLimit, PerPeerLimit: w.PerPeerLimit}
	r := &ReceiveCacheRec{Transition: t, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}
	if r.Mono < 0 || !validReceiveTransition(t) {
		return Record{}, fmt.Errorf("%w: invalid accepted-receive cache observation", ErrRecord)
	}
	return Record{Kind: KindReceiveCache, JSeq: w.JSeq, Body: r}, nil
}
