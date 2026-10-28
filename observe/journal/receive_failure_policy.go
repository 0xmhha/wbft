package journal

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/p2p/transport"
)

const ReceiveFailureCacheProfile uint64 = 1

// ErrReceiveFailureReplay distinguishes an understood diagnostic declaration
// from implemented functional replay or complete source reconstruction.
var ErrReceiveFailureReplay = errors.New("journal: receive failure cache replay profile is not available")

// ReceiveFailureCacheOptions declares an explicitly bounded local policy.
// Nil preserves every pre-existing header byte and JSON field.
type ReceiveFailureCacheOptions struct {
	Profile uint64 `json:"profile"`
	Entries uint64 `json:"entries"`
}

func (o *ReceiveFailureCacheOptions) Validate() error {
	if o != nil && (o.Profile != ReceiveFailureCacheProfile || o.Entries == 0 || o.Entries > transport.InmemoryMessages) {
		return fmt.Errorf("journal: unsupported receive failure cache declaration")
	}
	return nil
}

func (o *ReceiveFailureCacheOptions) encode() []uint64 {
	if o == nil {
		return nil
	}
	return []uint64{o.Profile, o.Entries}
}

func decodeReceiveFailureCacheOptions(raw []uint64) (*ReceiveFailureCacheOptions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) != 2 {
		return nil, fmt.Errorf("journal: receive failure cache field count")
	}
	// Unknown declarations remain inspectable; decoding grants no capability.
	return &ReceiveFailureCacheOptions{Profile: raw[0], Entries: raw[1]}, nil
}

func (o CoreOptions) validateReceiveFailureHeader() error {
	if err := o.ReceiveFailureCache.Validate(); err != nil {
		return err
	}
	if o.ReceiveFailureCache != nil {
		if o.CachePolicy == nil {
			return fmt.Errorf("journal: receive failure cache requires accepted-input policy declaration")
		}
		return o.CachePolicy.Validate()
	}
	return nil
}

// ValidateReceiveFailureDeclaration compares frozen values with actual local
// options. It grants neither replay nor verifier/source-checker capability.
func (o CoreOptions) ValidateReceiveFailureDeclaration(actual *transport.ReceiveFailureOptions) error {
	if err := o.validateReceiveFailureHeader(); err != nil {
		return err
	}
	if actual == nil {
		if o.ReceiveFailureCache != nil {
			return fmt.Errorf("journal: declared receive failure cache is not enabled")
		}
		return nil
	}
	if o.ReceiveFailureCache == nil || actual.Entries != o.ReceiveFailureCache.Entries {
		return fmt.Errorf("journal: receive failure cache differs from declaration")
	}
	return nil
}
