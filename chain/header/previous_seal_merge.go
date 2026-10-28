// SPDX-FileCopyrightText: 2026 The wbft authors
// SPDX-License-Identifier: LGPL-3.0-or-later

package header

import (
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/types"
)

// verifiedPreviousSeal binds a merge to the actual parent and its sealing set.
// A failed candidate may fall back only to a verified original aggregate.
// MergeSeals itself retains its original, unverified aggregation semantics.
func verifiedPreviousSeal(vs *validator.Set, parent *types.Header, round uint32, original *types.AggregatedSeal, extra []types.SealEntry, kind types.SealType) (*types.AggregatedSeal, error) {
	merged := MergeSeals(original, extra)
	if err := VerifyAggregatedSeal(vs, parent, round, merged, kind); err != nil {
		if merged == original {
			return nil, err
		}
		if originalErr := VerifyAggregatedSeal(vs, parent, round, original, kind); originalErr != nil {
			return nil, originalErr
		}
		return original, nil
	}
	return merged, nil
}
