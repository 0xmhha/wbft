package stepdriver

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// segmentDomain preserves the original writer's explicit declaration. It
// never manufactures a genesis identity from a CID or an input message.
func segmentDomain(segment *journal.SegmentRec) (*types.RoundChangeDomain, error) {
	if len(segment.Core.DomainBytes) > MaxApplicationAnswerBytes || len(segment.Core.DomainBytes) != 0 && len(segment.Core.ChainConfig) > MaxApplicationAnswerBytes-len(segment.Core.DomainBytes) {
		return nil, ErrTraceAnswerLimit
	}
	if err := segment.ValidateDomainIdentity(); err != nil {
		if errors.Is(err, journal.ErrDomainSourceUnsupported) || len(segment.Core.DomainBytes) == 0 && errors.Is(err, types.ErrRoundChangeDomain) {
			return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrTraceConfiguration, err)
	}
	return codec.DecodeRoundChangeDomain(segment.Core.DomainBytes)
}

func domainRuleConfigured(config *types.Config) bool {
	if config == nil {
		return false
	}
	_, configured := config.RuleActivation(types.RoundChangeDomainRule)
	return configured
}

type traceDomainOwner struct {
	declaration [32]byte
	selected    bool
}

// The optional prefix index stays finite even on a legacy-only stream. If
// that stream outgrows the index, legacy behavior continues; a later selected
// profile cannot claim the incomplete prefix as writer-consistency evidence.
type traceDomainIndex struct {
	owners              map[string]traceDomainOwner
	maxOwners, maxBytes int
	bytes               int
	selected, overflow  bool
}

func newTraceDomainIndex(maxOwners, maxBytes int) *traceDomainIndex {
	return &traceDomainIndex{owners: map[string]traceDomainOwner{}, maxOwners: maxOwners, maxBytes: maxBytes}
}

func (x *traceDomainIndex) observe(writer string, declaration [32]byte, selected bool) error {
	if x.overflow {
		if selected {
			return ErrTraceAnswerLimit
		}
		return nil
	}
	owner, known := x.owners[writer]
	if known && (owner.selected || selected) && owner.declaration != declaration {
		return ErrTraceConfiguration
	}
	if !known {
		remaining := x.maxBytes - x.bytes
		if len(x.owners) >= x.maxOwners || remaining < 33 || len(writer) > remaining-33 {
			if x.selected || selected {
				return ErrTraceAnswerLimit
			}
			x.owners, x.bytes, x.overflow = nil, 0, true
			return nil
		}
		x.bytes += len(writer) + 33
	}
	owner.declaration, owner.selected = declaration, owner.selected || selected
	x.owners[writer] = owner
	x.selected = x.selected || selected
	return nil
}
