package journal

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/p2p/transport"
)

const AcceptedCompletedCacheProfile uint64 = 1

// ErrCachePolicyReplay keeps an understood declaration distinct from an
// implemented functional replay capability. Physical reconstruction is separate.
var ErrCachePolicyReplay = errors.New("journal: cache policy replay profile is not available")

// CachePolicyOptions declares the runtime cache policy independently from
// consensus flags and the legacy cache_trace stream. Nil preserves old bytes.
type CachePolicyOptions struct {
	Profile uint64                      `json:"profile"`
	Limits  transport.CachePolicyLimits `json:"limits"`
}

func (o *CachePolicyOptions) Validate() error {
	if o == nil {
		return nil
	}
	if o.Profile != AcceptedCompletedCacheProfile {
		return fmt.Errorf("journal: unsupported cache policy profile %d", o.Profile)
	}
	return o.Limits.Validate()
}

func (o *CachePolicyOptions) encode() []uint64 {
	if o == nil {
		return nil
	}
	return []uint64{o.Profile, o.Limits.ReceivePending, o.Limits.ReceivePerPeer, o.Limits.WritePending, o.Limits.WritePerPeer}
}

func decodeCachePolicyOptions(raw []uint64) (*CachePolicyOptions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != 5 {
		return nil, errors.New("journal: cache policy field count")
	}
	// Preserve an unknown declaration for diagnosis. Decoding neither
	// enables the policy nor proves that a consumer can replay it.
	return &CachePolicyOptions{Profile: raw[0], Limits: transport.CachePolicyLimits{ReceivePending: raw[1], ReceivePerPeer: raw[2], WritePending: raw[3], WritePerPeer: raw[4]}}, nil
}

// ValidateRuntimeProfiles checks functional replay capability independently
// from record decoding. A recognized but unimplemented policy stays unavailable.
func (o CoreOptions) ValidateRuntimeProfiles() error {
	if err := o.NextHeight.Validate(); err != nil {
		return err
	}
	if err := o.CachePolicy.Validate(); err != nil {
		return err
	}
	if o.CachePolicy != nil {
		return ErrCachePolicyReplay
	}
	return nil
}
