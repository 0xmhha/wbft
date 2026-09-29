package privval

import (
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
)

func released(req VoteRequest) VoteRequest {
	req.BadBlockReleased = true
	return req
}

// A ROUND-CHANGE without a prepared pair after a COMMIT or after a
// ROUND-CHANGE with a pair in the same view is signed only when the request
// says that the bad-block rule released the pair; the mark does not lift the
// rules for a ROUND-CHANGE that carries a pair.
func TestBadBlockReleased(t *testing.T) {
	for _, restart := range []bool{false, true} {
		fs := fsys.NewMem()
		s := newTestSigner(t, fs)
		next := func() *FileSigner {
			if restart {
				return reopen(t, fs)
			}
			return s
		}
		mustSign(t, s, vote(codec.CodeCommit, view(10, 0), 1))
		// A failed finalize: ROUND-CHANGE (10, 1) with the pair of round 0.
		mustSign(t, s, roundChange(10, 1, rp(0), 1))
		s = next()
		// The bad-block rule released the pair: the same view without it.
		refused(t, s, roundChange(10, 1, nil, 0), ErrDoubleSign)
		a := mustSign(t, s, released(roundChange(10, 1, nil, 0)))
		s = next()
		if b := mustSign(t, s, released(roundChange(10, 1, nil, 0))); !b.Reused || string(a.Signature) != string(b.Signature) {
			t.Fatal("re-send of the released ROUND-CHANGE")
		}
		// Later rounds of the sequence: the COMMIT of round 0 still refuses
		// an unmarked ROUND-CHANGE without a pair.
		refused(t, s, roundChange(10, 2, nil, 0), ErrDoubleSign)
		mustSign(t, s, released(roundChange(10, 2, nil, 0)))
		// A new lock in a later round is signed as before.
		mustSign(t, s, vote(codec.CodeCommit, view(10, 3), 2))
		s = next()
		// The mark does not cover a ROUND-CHANGE that carries a pair below
		// the COMMIT round, nor a lower pair in the same view.
		refused(t, s, released(roundChange(10, 4, rp(2), 3)), ErrDoubleSign)
		mustSign(t, s, roundChange(10, 4, rp(3), 2))
		refused(t, s, released(roundChange(10, 4, rp(1), 3)), ErrDoubleSign)
	}
}
