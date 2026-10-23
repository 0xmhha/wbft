package journal

import "fmt"

// WriteAttemptSource references the actual original completed-write ledger
// reservation. It is separate from the legacy SendAttempt cache coordinates.
// Source presence does not prove a successful write, delivery or core ACCEPT.
type WriteAttemptSource struct {
	Sequence        uint64
	WriterRun       string
	Ledger, Request uint64
}

type writeAttemptRLP struct {
	Profile, Sequence uint64
	WriterRun         string
	Ledger, Request   uint64
}

func encodeWriteAttempt(a *WriteAttemptSource) ([]writeAttemptRLP, error) {
	if a == nil {
		return nil, nil
	}
	if a.Sequence == 0 || a.WriterRun == "" || a.Ledger == 0 || a.Request == 0 {
		return nil, fmt.Errorf("journal: incomplete write reservation source")
	}
	return []writeAttemptRLP{{Profile: 1, Sequence: a.Sequence, WriterRun: a.WriterRun, Ledger: a.Ledger, Request: a.Request}}, nil
}

func decodeWriteAttempt(w []writeAttemptRLP) (*WriteAttemptSource, error) {
	if len(w) == 0 {
		return nil, nil
	}
	if len(w) != 1 || w[0].Profile != 1 {
		return nil, fmt.Errorf("journal: invalid write reservation source")
	}
	a := &WriteAttemptSource{Sequence: w[0].Sequence, WriterRun: w[0].WriterRun, Ledger: w[0].Ledger, Request: w[0].Request}
	if _, err := encodeWriteAttempt(a); err != nil {
		return nil, err
	}
	return a, nil
}
