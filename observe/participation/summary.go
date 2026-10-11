package participation

import "slices"

// Summary aggregates the records of a range by validator
// (wbft_participationSummary, participation.md 5).
type Summary struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Heights is the number of records in the range, Gaps the number of
	// heights the node does not hold; Local counts the records of heights
	// this node's core saw.
	Heights int `json:"heights"`
	Gaps    int `json:"gaps"`
	Local   int `json:"local"`
	// Validators is sorted by address.
	Validators []ValidatorSummary `json:"validators"`
}

// ValidatorSummary is one validator's participation over the records of a
// range.
type ValidatorSummary struct {
	Validator string `json:"validator"`
	// Heights is the number of records whose validator set holds it.
	Heights int `json:"heights"`
	// ProposerRounds is the number of rounds it was the proposer of by the
	// proposer rule, Proposed the number of blocks it proposed (the
	// coinbase), and Missed the rounds it was the proposer of that ended
	// in a round change.
	ProposerRounds int `json:"proposerRounds"`
	Proposed       int `json:"proposed"`
	Missed         int `json:"missed"`
	// Sealed is the number of heights whose record of seals, the next
	// height's prev committed seal (WBFT-SEC-130), holds it; Late counts
	// those the height's own seals did not hold (extra seals).
	Sealed int `json:"sealed"`
	Late   int `json:"late"`
	// Delays are the first arrivals of its messages from peers with a known
	// round start, by code (preprepare, prepare, commit, roundChange). Only
	// records of heights this node's core saw have arrivals.
	Delays map[string]Delay `json:"delays"`
	// Evidence is the number of rounds with double-signing evidence of it.
	Evidence int `json:"evidence"`
}

// Delay is the count and the mean of arrival delays, in milliseconds.
type Delay struct {
	Count  int     `json:"count"`
	MeanMs float64 `json:"meanMs"`
}

// RoundChange is a round that ended in a round change
// (wbft_roundChanges, participation.md 5).
type RoundChange struct {
	Height   string `json:"height"`
	Round    string `json:"round"`    // the round left
	Proposer string `json:"proposer"` // its proposer by the proposer rule
	// Cause is why this node entered the next round (observe.md 2.3 item
	// 7); absent when the node did not see it (a record from the headers).
	Cause string `json:"cause,omitempty"`
	// Next is the round this node entered next, absent when unknown.
	Next string `json:"next,omitempty"`
}

// Summarize aggregates recs (the result of Range).
func Summarize(recs []Record) Summary {
	s := Summary{Validators: []ValidatorSummary{}}
	if len(recs) > 0 {
		s.From, s.To = recs[0].Height, recs[len(recs)-1].Height
	}
	by := map[string]*ValidatorSummary{}
	sums := map[string]map[string]int64{}
	get := func(a string) *ValidatorSummary {
		if v := by[a]; v != nil {
			return v
		}
		v := &ValidatorSummary{Validator: a, Delays: map[string]Delay{}}
		by[a], sums[a] = v, map[string]int64{}
		return v
	}
	for _, r := range recs {
		if r.Gap {
			s.Gaps++
			continue
		}
		s.Heights++
		if r.Source == "local" {
			s.Local++
		}
		for _, rd := range r.Rounds {
			if rd.Proposer == "" {
				continue
			}
			v := get(rd.Proposer)
			v.ProposerRounds++
			if rd.Outcome == "round_change" {
				v.Missed++
			}
		}
		if r.Proposer != "" {
			get(r.Proposer).Proposed++
		}
		for _, row := range r.Validators {
			v := get(row.Validator)
			if row.Round == r.Round {
				v.Heights++
				if row.InPrevCommitted {
					v.Sealed++
				}
				if row.Extra {
					v.Late++
				}
			}
			if row.Evidence {
				v.Evidence++
			}
			for code, seen := range map[string]*Seen{"preprepare": row.Preprepare, "prepare": row.Prepare, "commit": row.Commit, "roundChange": row.RoundChange} { //wbft:unordered sums commute
				if seen == nil || seen.DelayMs == nil || seen.Via == "self" {
					continue
				}
				d := v.Delays[code]
				d.Count++
				v.Delays[code] = d
				sums[row.Validator][code] += *seen.DelayMs
			}
		}
	}
	for a, v := range by { //wbft:unordered sorted below
		for code, d := range v.Delays { //wbft:unordered one entry each
			d.MeanMs = float64(sums[a][code]) / float64(d.Count)
			v.Delays[code] = d
		}
		s.Validators = append(s.Validators, *v)
	}
	slices.SortFunc(s.Validators, func(a, b ValidatorSummary) int {
		switch {
		case a.Validator < b.Validator:
			return -1
		case a.Validator > b.Validator:
			return 1
		}
		return 0
	})
	return s
}

// RoundChanges lists the rounds of recs that ended in a round change,
// oldest first.
func RoundChanges(recs []Record) []RoundChange {
	out := []RoundChange{}
	for _, r := range recs {
		for i, rd := range r.Rounds {
			if rd.Outcome != "round_change" {
				continue
			}
			c := RoundChange{Height: r.Height, Round: rd.Round, Proposer: rd.Proposer}
			// The next round this node entered, and why.
			for _, nx := range r.Rounds[i+1:] {
				if nx.Entered != nil {
					c.Cause, c.Next = nx.Cause, nx.Round
					break
				}
			}
			out = append(out, c)
		}
	}
	return out
}
