package runner

import (
	"fmt"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

func functionalHistorySelected(options consensus.Options) bool {
	return options.RoundChangeDomain != nil || options.Improvements.Has(consensus.DeferValidatorStart)
}

func functionalHistoryVersion(options consensus.Options) uint64 {
	if options.RoundChangeDomain != nil {
		return roundChangeDomainVersion
	}
	return validatorStartVersion
}

func functionalHistoryFormat(options consensus.Options) uint8 {
	if options.RoundChangeDomain != nil {
		return roundChangeDomainFormat
	}
	return validatorStartFormat
}

func freezeValidatorHistoryConfig(cfg *Config, log *wal.Log) error {
	cfg.Core.RoundChangeDomain = cfg.Core.RoundChangeDomain.Copy()
	if err := types.ValidateRoundChangeDomain(cfg.Core.Config, cfg.Core.RoundChangeDomain); err != nil {
		return err
	}
	deferSelected := cfg.Core.Improvements.Has(consensus.DeferValidatorStart)
	if !deferSelected && cfg.ValidatorHistory != nil {
		return fmt.Errorf("runner: validator-start history requires defer_validator_start")
	}
	selected := functionalHistorySelected(cfg.Core)
	if !selected {
		return nil
	}
	if cfg.Core.Improvements&^consensus.KnownImprovements() != 0 {
		return fmt.Errorf("runner: validator-start profile has unknown core options")
	}
	limits, err := validatorHistoryLimits(cfg.ValidatorHistory)
	if err != nil {
		return err
	}
	if log != nil && !cfg.ReplayWAL {
		return fmt.Errorf("runner: validator-start history requires WAL replay")
	}
	if log != nil && !log.OpenedStrict() {
		return fmt.Errorf("runner: validator-start history requires a strict WAL open")
	}
	if log != nil && log.Options().Header != nil {
		return fmt.Errorf("runner: validator-start history does not support automatic WAL headers")
	}
	// A domain-only effective default is not a public Defer override. Keeping
	// its input nil also makes repeated inspection/projection freezes stable.
	if deferSelected {
		cfg.ValidatorHistory = &limits
	}
	return nil
}
