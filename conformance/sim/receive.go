package sim

import (
	"fmt"

	"github.com/0xmhha/wbft/consensus/runner"
)

func cloneNextHeight(l *runner.NextHeightLimits, replay bool, processing *ProcessingProfile) (*runner.NextHeightLimits, error) {
	if l == nil {
		return nil, nil
	}
	if !replay || l.Entries == 0 || l.Bytes == 0 || l.PerPeer == 0 || l.PerSource == 0 {
		return nil, fmt.Errorf("%w: next-height receive requires WAL replay and four positive limits", ErrScenario)
	}
	if processing != nil {
		for _, cost := range processing.Costs {
			for _, sample := range cost.Samples {
				if sample > 0 {
					return nil, fmt.Errorf("%w: next-height receive requires atomic receive and core processing", ErrScenario)
				}
			}
		}
	}
	copyLimits := *l
	return &copyLimits, nil
}
