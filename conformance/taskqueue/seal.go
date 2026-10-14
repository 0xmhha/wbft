package taskqueue

// SealRequest identifies one asynchronous invocation and its proposal hash.
// It is independent of the synchronous caller model and task seal-hash map.
type SealRequest struct {
	ID   string
	Hash [32]byte
}
type Commit struct {
	ID       string
	Hash     [32]byte
	SealHash [32]byte
}
type SealResult struct {
	ID        string
	Commit    string
	Hash      [32]byte
	SealHash  [32]byte
	Cancelled bool
}
type SealKind uint8

const (
	MutexAcquired SealKind = iota
	RequestPostEntered
	RequestDelivered
	RequestPostReturned
	CommitAccepted
	CommitForwarded
	CommitDiscarded
	ResultSelected
	ResultSent
	MutexReleased
)

type SealEffect struct {
	ID        string
	Commit    string
	Kind      SealKind
	Cancelled bool
}
type sealInvocation struct {
	request                                    SealRequest
	stopped, entered, selected, sent, finished bool
	result                                     SealResult
}

// Sealer models one shared mutex, a capacity-one commit channel and a bounded
// result channel. The driver chooses competing stop/commit and mutex waiters.
// Posting the request is an independent goroutine, including after release.
type Sealer struct {
	runs              map[string]*sealInvocation
	posts             map[string]PostPhase
	commits           map[string]bool
	owner             string
	buffered, offered *Commit
	results           []SealResult
	capacity          int
}

func NewSealer(capacity int) (*Sealer, error) {
	if capacity < 1 || capacity > 65536 {
		return nil, ErrTransition
	}
	return &Sealer{runs: map[string]*sealInvocation{}, posts: map[string]PostPhase{}, commits: map[string]bool{}, results: []SealResult{}, capacity: capacity}, nil
}
func (s *Sealer) Owner() string { return s.owner }
func (s *Sealer) ProposedHash() [32]byte {
	if s.owner == "" {
		return [32]byte{}
	}
	return s.runs[s.owner].request.Hash
}
func (s *Sealer) ResultCount() int    { return len(s.results) }
func (s *Sealer) CommitBlocked() bool { return s.offered != nil }
func (s *Sealer) Begin(r SealRequest) error {
	if r.ID == "" || s.runs[r.ID] != nil {
		return ErrTransition
	}
	s.runs[r.ID] = &sealInvocation{request: r}
	return nil
}
func (s *Sealer) Acquire(id string) ([]SealEffect, error) {
	r := s.runs[id]
	if s.owner != "" || r == nil || r.entered {
		return nil, ErrTransition
	}
	r.entered = true
	s.owner = id
	s.posts[id] = PostReady
	return []SealEffect{{ID: id, Kind: MutexAcquired}}, nil
}

// Post phases preserve a blocked event-mux handoff independently of Seal.
type PostPhase uint8

const (
	PostUnknown PostPhase = iota
	PostReady
	PostEntered
	PostDelivered
	PostReturned
)

func (s *Sealer) PostPhase(id string) PostPhase { return s.posts[id] }
func (s *Sealer) BeginPost(id string) ([]SealEffect, error) {
	if s.posts[id] != PostReady {
		return nil, ErrTransition
	}
	s.posts[id] = PostEntered
	return []SealEffect{{ID: id, Kind: RequestPostEntered}}, nil
}
func (s *Sealer) DeliverPost(id string) ([]SealEffect, error) {
	if s.posts[id] != PostEntered {
		return nil, ErrTransition
	}
	s.posts[id] = PostDelivered
	return []SealEffect{{ID: id, Kind: RequestDelivered}}, nil
}

// ReturnPost without delivery represents an explicitly absent subscriber.
// A blocked subscriber must instead complete DeliverPost before returning.
func (s *Sealer) ReturnPost(id string, delivered bool) ([]SealEffect, error) {
	phase := s.posts[id]
	if delivered && phase != PostDelivered || !delivered && phase != PostEntered {
		return nil, ErrTransition
	}
	s.posts[id] = PostReturned
	return []SealEffect{{ID: id, Kind: RequestPostReturned}}, nil
}
func (s *Sealer) Cancel(id string) error {
	r := s.runs[id]
	if r == nil {
		return ErrTransition
	}
	r.stopped = true
	return nil
}

// OfferCommit captures the route when the core invokes Commit. A blocked send
// retains that route even if a different proposal owns the mutex later.
func (s *Sealer) OfferCommit(c Commit) ([]SealEffect, error) {
	if c.ID == "" || s.commits[c.ID] || s.offered != nil {
		return nil, ErrTransition
	}
	s.commits[c.ID] = true
	if c.Hash != s.ProposedHash() {
		return []SealEffect{{Commit: c.ID, Kind: CommitForwarded}}, nil
	}
	s.offered = &c
	return s.AcceptCommit()
}
func (s *Sealer) AcceptCommit() ([]SealEffect, error) {
	if s.offered == nil {
		return nil, ErrTransition
	}
	if s.buffered != nil {
		return []SealEffect{}, nil
	}
	s.buffered = s.offered
	s.offered = nil
	return []SealEffect{{Commit: s.buffered.ID, Kind: CommitAccepted}}, nil
}
func (s *Sealer) ChooseCommit(id string) ([]SealEffect, error) {
	r := s.runs[id]
	if s.owner != id || r == nil || r.selected || s.buffered == nil {
		return nil, ErrTransition
	}
	c := s.buffered
	s.buffered = nil
	if c.Hash != r.request.Hash {
		return []SealEffect{{ID: id, Commit: c.ID, Kind: CommitDiscarded}}, nil
	}
	r.selected = true
	r.result = SealResult{ID: id, Commit: c.ID, Hash: c.Hash, SealHash: c.SealHash}
	return []SealEffect{{ID: id, Commit: c.ID, Kind: ResultSelected}}, nil
}
func (s *Sealer) ChooseStop(id string) ([]SealEffect, error) {
	r := s.runs[id]
	if s.owner != id || r == nil || r.selected || !r.stopped {
		return nil, ErrTransition
	}
	r.selected = true
	r.result = SealResult{ID: id, Cancelled: true}
	return []SealEffect{{ID: id, Kind: ResultSelected, Cancelled: true}}, nil
}

// SendResult cannot release the mutex while the result channel is full. Even
// after a buffered send, sender resumption and deferred unlock are explicit.
func (s *Sealer) SendResult(id string) ([]SealEffect, error) {
	r := s.runs[id]
	if s.owner != id || r == nil || !r.selected || r.sent || len(s.results) >= s.capacity {
		return nil, ErrTransition
	}
	s.results = append(s.results, r.result)
	r.sent = true
	return []SealEffect{{ID: id, Commit: r.result.Commit, Kind: ResultSent, Cancelled: r.result.Cancelled}}, nil
}
func (s *Sealer) Release(id string) ([]SealEffect, error) {
	r := s.runs[id]
	if s.owner != id || r == nil || !r.sent || r.finished {
		return nil, ErrTransition
	}
	r.finished = true
	s.owner = ""
	return []SealEffect{{ID: id, Kind: MutexReleased}}, nil
}
func (s *Sealer) ReceiveResult() (SealResult, error) {
	if len(s.results) == 0 {
		return SealResult{}, ErrTransition
	}
	r := s.results[0]
	s.results = s.results[1:]
	return r, nil
}

// SealPhase exposes actor readiness without choosing a scheduling order.
type SealPhase uint8

const (
	SealUnknown SealPhase = iota
	WaitingMutex
	WaitingChoice
	WaitingResult
	WaitingRelease
	SealFinished
)

func (s *Sealer) Phase(id string) SealPhase {
	r := s.runs[id]
	if r == nil {
		return SealUnknown
	}
	if r.finished {
		return SealFinished
	}
	if r.sent {
		return WaitingRelease
	}
	if r.selected {
		return WaitingResult
	}
	if r.entered {
		return WaitingChoice
	}
	return WaitingMutex
}
func (s *Sealer) CommitReady() bool          { return s.buffered != nil }
func (s *Sealer) PostPending(id string) bool { return s.posts[id] == PostReady }
func (s *Sealer) StopReady(id string) bool   { r := s.runs[id]; return r != nil && r.stopped }
