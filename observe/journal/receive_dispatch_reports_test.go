package journal

import (
	"reflect"
	"testing"
)

// These are fresh unsigned inspection requests, with no live runner or input
// mutation. A prerequisite that did not run must never acquire a verdict.
func TestReceiveDispatchReportsUnavailablePrerequisites(t *testing.T) {
	for _, limits := range []ReceiveDispatchLimits{{}, {Operations: 1, Bytes: 1}} {
		got, err := CheckReceiveDispatchSourceReports(nil, limits)
		want, originalErr := CheckReceiveDispatchSources(nil, limits)
		if !reflect.DeepEqual(err, originalErr) || !reflect.DeepEqual(got.Dispatch, want) {
			t.Fatal("ordinary report or error changed", got.Dispatch, want, err, originalErr)
		}
		if got.Dispatch.Status != "unavailable" {
			t.Fatal("missing inspection evidence acquired a verdict", got.Dispatch)
		}
		if got.Core.Status != "unavailable" || got.Core.Reason != "not_inspected" ||
			got.Internal.Status != "unavailable" || got.Internal.Reason != "not_inspected" ||
			got.Inbox.Status != "unavailable" || got.Inbox.Reason != "not_inspected" ||
			got.Selections.Status != "unavailable" || got.Selections.Reason != "not_inspected" {
			t.Fatal("unreached prerequisite acquired a verdict", got)
		}
	}
}
