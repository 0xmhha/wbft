package journal

// ReceiveDispatchSourceReports contains actual prerequisite results from one
// ordinary receive-dispatch inspection. Inbox and Selections include the
// dispatch-qualified Known-discard evidence; they are not standalone reports
// when DiscardedKnown is nonzero. Unreached checks remain unavailable.
// These diagnostic values grant no signing, replay or runtime authority.
type ReceiveDispatchSourceReports struct {
	Core       CoreSourceCheck      `json:"core"`
	Internal   InternalCheck        `json:"internal"`
	Inbox      InboxCheck           `json:"inbox"`
	Selections SelectionCheck       `json:"selections"`
	Dispatch   ReceiveDispatchCheck `json:"dispatch"`
}

// CheckReceiveDispatchSourceReports performs the same ordinary inspection as
// CheckReceiveDispatchSources and also returns its independently recomputed
// prerequisite reports. It does not reuse caller-provided verdicts or models,
// skip checks, or establish a restored WAL boundary or physical execution.
func CheckReceiveDispatchSourceReports(records []Record, limits ReceiveDispatchLimits) (ReceiveDispatchSourceReports, error) {
	reports := ReceiveDispatchSourceReports{
		Core:       CoreSourceCheck{Status: "unavailable", Reason: "not_inspected"},
		Internal:   InternalCheck{Status: "unavailable", Reason: "not_inspected"},
		Inbox:      InboxCheck{Status: "unavailable", Reason: "not_inspected"},
		Selections: SelectionCheck{Status: "unavailable", Reason: "not_inspected"},
	}
	var err error
	reports.Dispatch, err = inspectReceiveDispatchReports(records, limits, nil, false, &reports)
	return reports, err
}
