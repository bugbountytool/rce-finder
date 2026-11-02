package patch

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/model"
)

func TestFixedWhenConfirmedThenNegative(t *testing.T) {
	before := Outcome{CandidateID: "c1", Build: "vulnerable", Status: model.StatusConfirmed}
	after := Outcome{CandidateID: "c1", Build: "patched", Status: model.StatusNotVulnerable}
	r, err := VerifyPatch("c1", before, after)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != VerdictFixed {
		t.Fatalf("verdict = %s", r.Verdict)
	}
}

func TestNotFixedWhenStillReproduces(t *testing.T) {
	before := Outcome{CandidateID: "c1", Status: model.StatusConfirmed}
	after := Outcome{CandidateID: "c1", Status: model.StatusConfirmed}
	r, _ := VerifyPatch("c1", before, after)
	if r.Verdict != VerdictNotFixed {
		t.Fatalf("verdict = %s", r.Verdict)
	}
}

func TestNoBaselineWhenBeforeUnconfirmed(t *testing.T) {
	before := Outcome{CandidateID: "c1", Status: model.StatusPotential}
	after := Outcome{CandidateID: "c1", Status: model.StatusNotVulnerable}
	r, _ := VerifyPatch("c1", before, after)
	if r.Verdict != VerdictNoBaseline {
		t.Fatalf("verdict = %s; an unconfirmed baseline cannot prove a patch", r.Verdict)
	}
}

func TestInconclusiveAfterError(t *testing.T) {
	before := Outcome{CandidateID: "c1", Status: model.StatusConfirmed}
	after := Outcome{CandidateID: "c1", Status: model.StatusError}
	r, _ := VerifyPatch("c1", before, after)
	if r.Verdict != VerdictInconclusive {
		t.Fatalf("verdict = %s", r.Verdict)
	}
}

func TestMismatchedCandidatesRejected(t *testing.T) {
	before := Outcome{CandidateID: "c1", Status: model.StatusConfirmed}
	after := Outcome{CandidateID: "c2", Status: model.StatusNotVulnerable}
	if _, err := VerifyPatch("c1", before, after); err == nil {
		t.Fatal("mismatched candidates accepted")
	}
}
