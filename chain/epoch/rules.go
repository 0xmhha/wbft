// Copyright 2025 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
package epoch

import (
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// ruleForEpochHeader resolves activation from the actual parent before any
// classification using the supplied number. An active call must be its child.
func ruleForEpochHeader(chain types.ChainReader, cfg *types.Config, e *types.Header, rule types.RuleName) (bool, error) {
	if _, configured := cfg.RuleActivation(rule); !configured || e.Number.IsZero() && e.ParentHash == (types.Hash{}) {
		return false, nil
	}
	parent := chain.HeaderByHash(e.ParentHash)
	if parent == nil || codec.BlockHash(parent) != e.ParentHash {
		return false, validator.ErrUnknownAncestor
	}
	next := parent.Number.AddUint64(1)
	active := cfg.Rules(rule, next)
	if active && e.Number.Cmp(next) != 0 {
		return false, validator.ErrUnknownAncestor
	}
	return active, nil
}
