package runner

import "github.com/0xmhha/wbft/observe/journal"

// TimerSourceObserver receives detached scheduler mutations independently of
// the functional journal. It runs after the timer mutex is released and must
// return promptly. Clock callbacks can deliver concurrently and out of order;
// Sequence records the original mutex order. Retaining or altering the value
// never changes timer ownership, input bytes or a legacy journal record.
// Zero Sequence marks exhausted observation metadata and is never reused.
// This optional diagnostic hook does not enable functional runtime replay.
type TimerSourceObserver interface{ ObserveTimerSource(journal.TimerRec) }

func (s *scheduler) publish(records ...*journal.TimerRec) {
	if s.observe == nil {
		return
	}
	for _, record := range records {
		if record != nil {
			s.observe(*record)
		}
	}
}
