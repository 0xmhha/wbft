package consensus

import (
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// RoundChangeRetryOptions enables additional current-view own round-change
// attempts with exponential spacing. Nil preserves the original policy.
// MaxIntervalMs is an explicit local bound, independent of round timeouts.
type RoundChangeRetryOptions struct {
	MaxIntervalMs uint64 `json:"max_interval_ms,string"`
}

// Copy freezes the caller's single local parameter.
func (o *RoundChangeRetryOptions) Copy() *RoundChangeRetryOptions {
	if o == nil {
		return nil
	}
	c := *o
	return &c
}

// Validate checks every effective timeout from the first consensus height.
// This bound limits retry spacing, not payload size or total process memory.
func (o *RoundChangeRetryOptions) Validate(config *types.Config) error {
	if o == nil {
		return nil
	}
	if config == nil || o.MaxIntervalMs == 0 || o.MaxIntervalMs > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return fmt.Errorf("consensus: round-change retry requires configuration and a positive representable maximum interval")
	}
	if err := config.CheckTransitions(); err != nil {
		return err
	}
	check := func(height types.Height) error {
		base := config.ConfigAt(height).RequestTimeoutMs
		if base == 0 || base > o.MaxIntervalMs {
			return fmt.Errorf("consensus: retry maximum is below the positive base timeout at height %s", height)
		}
		return nil
	}
	if err := check(types.HeightFromUint64(1)); err != nil {
		return err
	}
	for _, transition := range config.Transitions() {
		height, err := types.HeightFromBig(transition.Block)
		if err != nil {
			return err
		}
		if !height.IsZero() {
			if err := check(height); err != nil {
				return err
			}
		}
	}
	return nil
}

type roundChangeRetryState struct {
	valid    bool
	view     types.View
	key      types.Hash
	exponent uint64
}

// CurrentRoundChangeRetry checks functional timer ownership on the core's
// goroutine before Step consumes the expiry or arms its successor.
func (s *State) CurrentRoundChangeRetry(t Timeout) bool {
	return s.opt.RoundChangeRetry != nil && s.running && s.cur != nil && t.Kind == RetryTimer &&
		s.retryLive && t.Gen == s.gen[RetryTimer] && t.View.Cmp(s.cur.view) == 0 &&
		t.Round.Cmp(s.cur.view.Round) == 0 && s.state == AcceptRequest
}

// RoundChangeRetryIntent belongs to an actual live current-view timer input.
// It is a core output for the owning runner, not authority from an event label.
type RoundChangeRetryIntent struct {
	View       types.View
	Generation uint64
	Key        types.Hash
}

// RoundChangeRetryArm describes the local policy used for a timer duration.
// Known separates a current candidate identity from an initial rearm.
type RoundChangeRetryArm struct {
	Known         bool
	Key           types.Hash
	Exponent      uint64
	MaxIntervalMs uint64
}

// retryInterval saturates before multiplication and performs bounded work.
// The options validator makes the final duration conversion representable.
func retryInterval(base, maximum, exponent uint64) time.Duration {
	d := base
	for i := uint64(0); i < exponent && d < maximum; i++ {
		if d > maximum/2 {
			d = maximum
		} else {
			d *= 2
		}
	}
	if d > maximum {
		d = maximum
	}
	return time.Duration(d) * time.Millisecond
}

func roundChangeRetryKey(message *codec.Message) (types.Hash, error) {
	return roundChangeRetryKeyWithDomain(message, nil)
}

func roundChangeRetryKeyWithDomain(message *codec.Message, domain *types.RoundChangeDomain) (types.Hash, error) {
	if message == nil || message.Code != codec.CodeRoundChange {
		return types.Hash{}, fmt.Errorf("consensus: retry identity requires a round-change")
	}
	body, err := codec.SigningPayloadWithDomain(message, domain)
	if err != nil {
		return types.Hash{}, err
	}
	return codec.DedupKey(body), nil
}

func (r *roundChangeRetryState) prepare(view types.View, key types.Hash, timerRetry bool) {
	if !r.valid || r.view.Cmp(view) != 0 || r.key != key {
		*r = roundChangeRetryState{valid: true, view: view, key: key}
		return
	}
	// A useful exponent never exceeds the duration's bit width. Repeated
	// timer intent cannot wrap the counter or depend on queue outcomes.
	if timerRetry && r.exponent < 63 {
		r.exponent++
	}
}
