package journal

import (
	"fmt"
	"math"
	"time"
)

// IOInterval is optional transport timing evidence. Mono shares the journal's
// clock origin. Wall-clock regressions remain observable, never corrected.
type IOInterval struct {
	StartMono, EndMono     time.Duration
	StartWallNs, EndWallNs int64
}

func encodeIO(io *IOInterval, observed time.Duration) ([]uint64, error) {
	if io == nil {
		return nil, nil
	}
	if io.StartMono < 0 || io.EndMono < io.StartMono || io.EndMono > observed {
		return nil, fmt.Errorf("journal: invalid I/O interval")
	}
	return []uint64{uint64(io.StartMono), uint64(io.StartWallNs), uint64(io.EndMono), uint64(io.EndWallNs)}, nil
}

func decodeIO(raw []uint64, observed time.Duration) (*IOInterval, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != 4 || raw[0] > math.MaxInt64 || raw[2] > math.MaxInt64 {
		return nil, fmt.Errorf("journal: malformed I/O interval")
	}
	io := &IOInterval{StartMono: time.Duration(raw[0]), StartWallNs: int64(raw[1]), EndMono: time.Duration(raw[2]), EndWallNs: int64(raw[3])}
	if _, err := encodeIO(io, observed); err != nil {
		return nil, err
	}
	return io, nil
}
