package consensus

import (
	"math"
	"strconv"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// allowFutureWait compares lengths, not an inferred remaining deadline. The
// existing nonpositive-duration behavior is retained independently of this
// local positive-wait policy.
func (st *step) allowFutureWait(block *types.Block, wait time.Duration, origin string) bool {
	s := st.s
	if !s.opt.Improvements.Has(LimitFutureProposalWait) || wait <= 0 {
		return true
	}
	params := s.config(s.cur.view.Sequence)
	if params.RequestTimeoutMs == 0 || params.RequestTimeoutMs > uint64(math.MaxInt64/int64(time.Millisecond)) || params.MaxRequestTimeoutSeconds > uint64(math.MaxInt64/int64(time.Second)) {
		return true
	}
	limit, _ := roundTimeoutWithOptions(params, s.cur.view.Round, s.opt.Improvements)
	if limit <= 0 || wait <= limit {
		return true
	}
	st.emit(Event{Record: event.Record{
		Kind: event.Health,
		View: event.ViewOf(s.cur.view),
		Fields: map[string]any{
			"what":            "future_proposal_wait_exceeded",
			"h":               s.cur.view.Sequence.String(),
			"hash":            hexHash(blockHash(block)),
			"proposal_origin": origin,
			"wait_ns":         strconv.FormatInt(int64(wait), 10),
			"limit_ns":        strconv.FormatInt(int64(limit), 10),
		},
	}})
	return false
}
