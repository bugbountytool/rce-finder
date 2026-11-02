// Package patch verifies that a remediation actually removes a vulnerability.
// It re-runs a finding's original validation against a patched build and
// confirms the finding no longer reproduces, producing a regression record.
//
// Patch verification compares a before/after pair of verification outcomes for
// the same candidate. A finding is "fixed" only when it was confirmed before
// and is no longer reproducible after, with the same plan and scope.
package patch

import (
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// Outcome is the verification result for one candidate against one build.
type Outcome struct {
	CandidateID string
	Build       string // "vulnerable" or "patched" (operator-labeled)
	Status      model.Status
}

// Verdict is the result of a patch verification.
type Verdict string

const (
	VerdictFixed        Verdict = "FIXED"         // confirmed before, not reproducible after
	VerdictNotFixed     Verdict = "NOT_FIXED"     // still reproduces after the patch
	VerdictInconclusive Verdict = "INCONCLUSIVE"  // could not establish a before/after
	VerdictNoBaseline   Verdict = "NO_BASELINE"   // no confirmed baseline to compare
)

// Result is a patch-verification record.
type Result struct {
	CandidateID string
	Before      model.Status
	After       model.Status
	Verdict     Verdict
	Detail      string
}

// VerifyPatch compares a before/after pair for the same candidate. The same
// validation plan and scope must have been used for both; the caller is
// responsible for that. A patch is only "FIXED" when a previously confirmed
// finding no longer reproduces.
func VerifyPatch(candidateID string, before, after Outcome) (Result, error) {
	if before.CandidateID != candidateID || after.CandidateID != candidateID {
		return Result{}, fmt.Errorf("outcomes do not match candidate %s", candidateID)
	}
	r := Result{CandidateID: candidateID, Before: before.Status, After: after.Status}
	wasConfirmed := before.Status == model.StatusConfirmed || before.Status == model.StatusHighConfidence
	stillReproduces := after.Status == model.StatusConfirmed || after.Status == model.StatusHighConfidence

	switch {
	case !wasConfirmed:
		r.Verdict = VerdictNoBaseline
		r.Detail = "no confirmed baseline; cannot verify a patch against an unconfirmed candidate"
	case wasConfirmed && !stillReproduces && (after.Status == model.StatusNotVulnerable || after.Status == model.StatusInconclusive || after.Status == model.StatusPotential):
		r.Verdict = VerdictFixed
		r.Detail = "finding was confirmed before and no longer reproduces after the patch"
	case stillReproduces:
		r.Verdict = VerdictNotFixed
		r.Detail = "finding still reproduces after the patch; remediation is incomplete"
	default:
		r.Verdict = VerdictInconclusive
		r.Detail = "after-state did not establish a clear negative; re-run validation"
	}
	return r, nil
}
