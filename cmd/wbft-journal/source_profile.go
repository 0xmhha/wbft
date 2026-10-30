package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

var errSourceProfile = errors.New("journal: invalid source profile")

func unsupportedSourceProfile(err error) bool {
	return errors.Is(err, journal.ErrSignerSourceUnsupported) || errors.Is(err, journal.ErrDomainSourceUnsupported) || errors.Is(err, types.ErrRoundChangeDomainVersion)
}

// R01 has no field that can bind this profile to its original chain identity.
// Refuse it before the own-input index can use a legacy recovery operation.
func r01DomainProfile(segment *journal.SegmentRec) error {
	if err := validateSourceRecord(journal.Record{Body: segment}); err != nil {
		return err
	}
	if len(segment.Core.DomainBytes) != 0 {
		return fmt.Errorf("%w: R01 cannot preserve the declared domain; use the original journal or bundle", journal.ErrDomainSourceUnsupported)
	}
	return nil
}

func r01RecordProfile(record journal.Record) error {
	switch body := record.Body.(type) {
	case *journal.SegmentRec:
		return r01DomainProfile(body)
	case *journal.CoreStepRec:
		if len(body.DomainBytes) != 0 {
			return journal.ErrDomainSourceUnsupported
		}
	case *journal.SignerRec:
		if body.Source.Version == privval.DomainSourceVersion {
			return journal.ErrDomainSourceUnsupported
		}
	}
	return nil
}

func validateSourceRecord(record journal.Record) error {
	if segment, ok := record.Body.(*journal.SegmentRec); ok {
		if err := segment.ValidateDomainIdentity(); err != nil {
			if len(segment.Core.DomainBytes) == 0 && errors.Is(err, types.ErrRoundChangeDomain) {
				err = fmt.Errorf("%w: selected segment has no domain declaration", journal.ErrDomainSourceUnsupported)
			}
			return fmt.Errorf("%w: %w", errSourceProfile, err)
		}
	}
	return nil
}

func readSourceRecord(reader *journal.Reader) (journal.Record, error) {
	record, err := reader.Next()
	if err == nil {
		err = validateSourceRecord(record)
	}
	return record, err
}

// One streaming preflight precedes every own-message recovery and output.
// It retains no source payloads. Generic legacy damaged-prefix behavior remains
// with the ordinary export pass; recognized profiles cannot use that fallback.
func r01ProfilePreflight(fs fsys.FS, dir string) ([32]byte, bool, error) {
	var profile error
	stream := sha256.New()
	encoder := json.NewEncoder(stream)
	err := scan(fs, dir, func(record journal.Record, pos wal.Position) {
		if profile == nil {
			profile = r01RecordProfile(record)
			if profile == nil {
				profile = encodeOwnStream(encoder, record, pos)
			}
		}
	})
	if profile != nil {
		return [32]byte{}, false, profile
	}
	if unsupportedSourceProfile(err) || errors.Is(err, errSourceProfile) {
		return [32]byte{}, false, err
	}
	return ownStreamSum(stream), err == nil, nil
}

// Preserve each check command's report schema. Other commands use an explicit
// unavailable envelope; no successfully checked prefix is implied.
func unsupportedCommandResult(command string) any {
	const reason = "unsupported_source_profile"
	switch command {
	case "check-write-cache":
		return journal.WriteCacheCheck{Status: "unavailable", Reason: reason, PhysicalStatus: "unavailable"}
	case "check-receive-cache":
		return journal.ReceiveCacheCheck{Status: "unavailable", Reason: reason, PhysicalStatus: "unavailable"}
	case "check-write-io":
		return journal.WriteIOCheck{Status: "unavailable", Reason: reason, PhysicalStatus: "unavailable"}
	case "check-round-change-retry":
		return journal.RetrySourceCheck{Status: "unavailable", Reason: reason, PhysicalStatus: "unavailable", Scope: "original_retry_owner_timer_signer_wal_cache_bindings"}
	case "check-receive-failures":
		return journal.ReceiveFailureCheck{Status: "unavailable", Reason: reason, PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", Scope: "original_failure_checks_bounded_cache_and_inbox_consumption"}
	default:
		return map[string]string{"status": "unavailable", "reason": reason, "scope": "journal_" + command, "physical_status": "unavailable"}
	}
}
