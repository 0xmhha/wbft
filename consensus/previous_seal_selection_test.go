// SPDX-FileCopyrightText: 2026 The wbft authors
// SPDX-License-Identifier: LGPL-3.0-or-later

package consensus

import "testing"

func TestVerifiedPreviousSealSelection(t *testing.T) {
	selected, ok := ParseImprovement("verify_merged_prev_seals")
	if !ok || selected != VerifyMergedPrevSeals || !KnownImprovements().Has(selected) {
		t.Fatal("explicit previous seal verification selection is unavailable")
	}
	if RestartSafety.Has(selected) || uint(BindPriorHead) != 21 || uint(selected) != 22 {
		t.Fatal("selection changed an old flag bit or enabled itself by default")
	}
	names := ImprovementSet(0).With(selected).Names()
	if len(names) != 1 || names[0] != "verify_merged_prev_seals" {
		t.Fatal("selected local behavior lost its reported name", names)
	}
}
