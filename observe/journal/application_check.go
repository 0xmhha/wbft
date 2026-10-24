package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// ApplicationRoot is an independently supplied, profile-specific public
// genesis or parent-state witness. Data must be allowlisted by the provider;
// node homes, secret keys, live DB handles and observed results are not inputs.
type ApplicationRoot struct {
	Profile string
	Parent  types.Hash
	Data    []byte
}

// ApplicationFactory opens an isolated instance from the conditional root.
// It must not reuse the original application, its DB, its built-result cache or
// observed responses. Import must execute the original transactions and normal
// validation/finalization rules, then return the independently computed header.
// The checker cannot establish the correctness of the provider implementation.
type ApplicationFactory interface {
	Open(context.Context, ApplicationRoot) (ApplicationInstance, error)
}
type ApplicationInstance interface {
	Import(context.Context, *types.Block, types.Round) (*types.Header, error)
	Close() error
}

var ErrApplicationUnavailable = errors.New("journal: application provider unavailable")
var ErrApplicationSource = errors.New("journal: inconsistent application source")

type ApplicationLimits struct {
	Finalize     FinalizeLimits
	Calls, Bytes uint64
}
type ApplicationCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	SourceStatus   string `json:"source_status"`
	PhysicalStatus string `json:"physical_status"`
	Calls          uint64 `json:"calls,string"`
}

// CheckApplicationSources executes a separate provider after source validation.
// Roots are keyed by original writer run; none is inferred from an app response.
// A finite horizon with an unfinished call stays unavailable. Physical storage
// and the complete runtime schedule are outside this conditional check.
func CheckApplicationSources(ctx context.Context, records []Record, roots map[string]ApplicationRoot, factory ApplicationFactory, limits ApplicationLimits) (ApplicationCheck, error) {
	return checkApplicationSources(ctx, records, roots, factory, limits, false)
}

// CheckRestoredApplicationSources is the explicit restored-prefix inspection
// path. It first reconstructs original WAL selection, installed core state and
// restore effects. Ordinary CheckApplicationSources retains its restore guard.
// Every dependent inspection builds fresh private seeds; no mutable model or
// caller-supplied certificate is shared between them.
func CheckRestoredApplicationSources(ctx context.Context, records []Record, roots map[string]ApplicationRoot, factory ApplicationFactory, limits ApplicationLimits) (ApplicationCheck, error) {
	restore, core, err := CheckRestoredCoreSources(records, limits.Finalize.Queue.Core)
	reason := ""
	if restore.Status != "consistent" {
		reason = "restore_" + restore.Reason
	} else if core.Status != "consistent" {
		reason = "core_" + core.Reason
	}
	if err == nil && reason == "" {
		hasRestored := false
		for _, row := range records {
			if source, ok := row.Body.(*RestoreRec); ok && source.Replayed != 0 {
				hasRestored = true
			}
		}
		if hasRestored {
			_, _, effects, e := CheckRestoredBoundarySources(records, limits.Finalize.Queue.Core)
			err = e
			if effects.Status != "consistent" {
				reason = "effects_" + effects.Reason
			}
		}
	}
	if err != nil || reason != "" {
		report := ApplicationCheck{Status: "unavailable", Reason: reason, Scope: "independent_application_on_public_root_witness_and_restored_core", SourceStatus: "unavailable", PhysicalStatus: "unavailable"}
		if err != nil {
			report.Status = "inconsistent"
		}
		return report, err
	}
	report, err := checkApplicationSources(ctx, records, roots, factory, limits, true)
	report.Scope = "independent_application_on_public_root_witness_and_restored_core"
	return report, err
}

func inspectApplicationCoreOutputs(records []Record, limits CoreSourceLimits, restored bool, capture func(string, *CoreStepRec, []consensus.Output)) (CoreSourceCheck, []coreSourceAccepted, error) {
	return inspectConditionalCoreStates(records, limits, restored, capture, nil)
}

// Every conditional inspection creates fresh private restored state. Output
// and snapshot consumers never receive a runner-owned model or caller proof.
func inspectConditionalCoreStates(records []Record, limits CoreSourceLimits, restored bool, capture func(string, *CoreStepRec, []consensus.Output), snapshots func(string, *CoreStepRec, *consensus.Snapshot)) (CoreSourceCheck, []coreSourceAccepted, error) {
	if !restored {
		return inspectCoreSourceStates(records, limits, capture, snapshots)
	}
	restore, seeds, err := reconstructRestoreSources(records, limits)
	if err != nil || restore.Status != "consistent" {
		return CoreSourceCheck{Status: "unavailable", Reason: "restore_not_reconstructed"}, nil, err
	}
	return inspectCoreSourceStatesRestored(records, limits, capture, snapshots, seeds)
}

func checkApplicationSources(ctx context.Context, records []Record, roots map[string]ApplicationRoot, factory ApplicationFactory, limits ApplicationLimits, restored bool) (report ApplicationCheck, checkErr error) {
	report = ApplicationCheck{Status: "unavailable", Scope: "independent_application_on_public_root_witness", SourceStatus: "unavailable", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (ApplicationCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (ApplicationCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrApplicationSource, reason)
	}
	if factory == nil {
		return unavailable("provider_missing")
	}
	if limits.Calls == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	sources, err := checkFinalizeSources(records, limits.Finalize, restored)
	report.SourceStatus = sources.Status
	if err != nil {
		return bad("finalize_" + sources.Reason)
	}
	if sources.Status != "consistent" {
		return unavailable("finalize_" + sources.Reason)
	}
	if sources.RetainedActive != 0 || sources.RetainedReturned != 0 || sources.RetainedQueued != 0 {
		return unavailable("unfinished_finalize_tasks")
	}
	type key struct {
		run  string
		task uint64
	}
	type call struct {
		enter, returned                      *FinalizeRec
		source                               *ApplicationRec
		enterIndex, returnIndex, sourceIndex int
	}
	calls := map[key]*call{}
	order := []key{}
	writer := ""
	var span uint64
	charge := func(n uint64) bool {
		if n > limits.Bytes-span {
			return false
		}
		span += n
		return true
	}
	for index, row := range records {
		switch s := row.Body.(type) {
		case *SegmentRec:
			writer = s.Run
		case *GapRec:
			if s.Dropped > 0 && len(s.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range s.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindApplication)) {
					return unavailable("application_gap")
				}
			}
		case *FinalizeRec:
			k := key{writer, s.Task}
			switch s.Action {
			case "enter":
				if uint64(len(calls)) >= limits.Calls {
					return unavailable("call_limit")
				}
				if calls[k] != nil {
					return bad("call_reused")
				}
				if !charge(uint64(len(s.Arguments))) {
					return unavailable("byte_limit")
				}
				calls[k] = &call{enter: s, enterIndex: index}
				order = append(order, k)
			case "return":
				c := calls[k]
				if c == nil || c.returned != nil {
					return bad("return_owner_changed")
				}
				c.returned, c.returnIndex = s, index
			}
		case *ApplicationRec:
			if !validApplicationRec(s) {
				return bad("invalid_application_source")
			}
			if s.Unavailable != "" {
				return unavailable("application_" + s.Unavailable)
			}
			k := key{s.Source.Run, s.Source.Task}
			c := calls[k]
			if k.run != writer || c == nil || c.source != nil {
				return bad("application_owner_or_order_changed")
			}
			if !charge(uint64(size(row))) {
				return unavailable("byte_limit")
			}
			c.source, c.sourceIndex = s, index
		}
	}
	if len(order) == 0 {
		return unavailable("application_call_missing")
	}
	instances := map[string]ApplicationInstance{}
	defer func() {
		for _, instance := range instances {
			if err := instance.Close(); err != nil && checkErr == nil {
				report.Status, report.Reason = "unavailable", "provider_close_failed"
				checkErr = fmt.Errorf("%w: provider_close_failed", ErrApplicationUnavailable)
			}
		}
	}()
	for _, k := range order {
		if err := ctx.Err(); err != nil {
			return unavailable("inspection_canceled")
		}
		c := calls[k]
		s := c.source
		if s == nil || c.returned == nil {
			return unavailable("application_boundary_missing")
		}
		if c.enterIndex >= c.sourceIndex || c.sourceIndex >= c.returnIndex || s.Source.Engine != c.enter.EngineRun || s.Source.Step != c.enter.Step || s.Source.Output != c.enter.Output || !bytes.Equal(s.Arguments, c.enter.Arguments) || s.EntryMono < uint64(c.enter.Mono) || s.Mono > uint64(c.returned.Mono) || (s.Result == "error") != c.returned.HasError {
			return bad("application_boundary_changed")
		}
		if s.Result != "ok" {
			return unavailable("failed_application_not_supported")
		}
		commit, err := decodeApplicationCommit(s.Arguments)
		if err != nil {
			return bad("application_arguments_invalid")
		}
		hash := codec.BlockHash(commit.Block.Header)
		if s.Hash != hash {
			return bad("application_response_hash_changed")
		}
		instance := instances[k.run]
		if instance == nil {
			root, ok := roots[k.run]
			if !ok || root.Profile == "" || len(root.Data) == 0 {
				return unavailable("root_witness_missing")
			}
			if root.Parent != commit.Block.Header.ParentHash {
				return unavailable("root_parent_not_available")
			}
			if !charge(uint64(len(root.Profile) + len(root.Data))) {
				return unavailable("byte_limit")
			}
			root.Data = bytes.Clone(root.Data)
			instance, err = factory.Open(ctx, root)
			if errors.Is(err, ErrApplicationUnavailable) {
				return unavailable("root_or_profile_not_supported")
			}
			if err != nil || instance == nil {
				return unavailable("provider_open_failed")
			}
			instances[k.run] = instance
		}
		// DecodeOutputs created an owned block; no runtime-owned object or
		// recorded response is passed to the independent provider.
		computed, err := instance.Import(ctx, commit.Block, commit.Round)
		if errors.Is(err, ErrApplicationUnavailable) {
			return unavailable("provider_input_not_supported")
		}
		if err != nil {
			return bad("independent_application_failed")
		}
		if computed == nil || codec.BlockHash(computed) != hash {
			return bad("independent_application_result_changed")
		}
		report.Calls++
	}
	report.Status = "consistent_on_public_root_witness"
	return report, nil
}

func decodeApplicationCommit(raw []byte) (consensus.Commit, error) {
	var list []rlp.RawValue
	if err := rlp.DecodeStrict(raw, &list); err != nil || len(list) != 1 {
		return consensus.Commit{}, ErrApplicationSource
	}
	var wire struct {
		Tag   uint64
		Block []byte
		Round *big.Int
	}
	if err := rlp.DecodeStrict(list[0], &wire); err != nil || wire.Tag != 7 {
		return consensus.Commit{}, ErrApplicationSource
	}
	block, err := codec.DecodeBlock(wire.Block)
	if err != nil || block == nil || block.Header == nil {
		return consensus.Commit{}, ErrApplicationSource
	}
	round, err := types.RoundFromBig(wire.Round)
	if err != nil {
		return consensus.Commit{}, ErrApplicationSource
	}
	commit := consensus.Commit{Block: block, Round: round}
	canonical, err := inputlog.EncodeOutputs([]consensus.Output{commit})
	if err != nil || !bytes.Equal(canonical, raw) {
		return consensus.Commit{}, ErrApplicationSource
	}
	return commit, nil
}
