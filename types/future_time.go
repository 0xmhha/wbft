package types

// FutureTimeAllowanceAt returns the nonzero future-time allowance inherited
// through the already sorted transitions at the full height. Zero and absent
// transition values both inherit the preceding value. ConfigAt retains its
// reference behavior independently of this explicit query.
func (c *Config) FutureTimeAllowanceAt(number Height) uint64 {
	allowance := c.base.AllowedFutureBlockTime
	n := number.big()
	for _, transition := range c.transitions {
		if transition.Block == nil || transition.Block.Cmp(n) > 0 {
			break
		}
		if transition.WBFT != nil && transition.WBFT.AllowedFutureBlockTime != 0 {
			allowance = transition.WBFT.AllowedFutureBlockTime
		}
	}
	return allowance
}
