package runner

import (
	"fmt"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
)

func freezeValidatorHistoryConfig(cfg *Config, log *wal.Log) error {
	selected := cfg.Core.Improvements.Has(consensus.DeferValidatorStart)
	if !selected {
		if cfg.ValidatorHistory != nil {
			return fmt.Errorf("runner: validator-start history requires defer_validator_start")
		}
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
	if log != nil && log.Options().Header != nil {
		return fmt.Errorf("runner: validator-start history does not support automatic WAL headers")
	}
	cfg.ValidatorHistory = &limits
	return nil
}
