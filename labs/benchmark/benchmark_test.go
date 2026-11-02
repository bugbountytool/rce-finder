package benchmark

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/model"
)

func TestComputeMetrics(t *testing.T) {
	cases := []Case{
		{Name: "vuln1", Vulnerable: true, Status: model.StatusConfirmed},
		{Name: "vuln2", Vulnerable: true, Status: model.StatusHighConfidence},
		{Name: "vuln3", Vulnerable: true, Status: model.StatusNotVulnerable}, // FN
		{Name: "patched1", Vulnerable: false, Status: model.StatusNotVulnerable}, // TN
		{Name: "patched2", Vulnerable: false, Status: model.StatusPotential},      // not reported -> TN
		{Name: "patched3", Vulnerable: false, Status: model.StatusConfirmed},      // FP + false confirm
	}
	m, err := Compute(cases)
	if err != nil {
		t.Fatal(err)
	}
	if m.TruePositives != 2 || m.FalseNegatives != 1 || m.TrueNegatives != 2 || m.FalsePositives != 1 {
		t.Fatalf("confusion = %+v", m)
	}
	if m.Precision != 2.0/3.0 {
		t.Fatalf("precision = %f", m.Precision)
	}
	if m.Recall != 2.0/3.0 {
		t.Fatalf("recall = %f", m.Recall)
	}
	// One of three non-vulnerable fixtures was CONFIRMED.
	if m.FalseConfirmationRate != 1.0/3.0 {
		t.Fatalf("false confirmation rate = %f", m.FalseConfirmationRate)
	}
}

func TestEmptyCasesError(t *testing.T) {
	if _, err := Compute(nil); err == nil {
		t.Fatal("empty benchmark reported metrics instead of an error")
	}
}

func TestPotentialIsNotADetection(t *testing.T) {
	// A vulnerable fixture classified POTENTIAL is a false negative for
	// detection purposes, not a true positive.
	m, _ := Compute([]Case{{Name: "v", Vulnerable: true, Status: model.StatusPotential}})
	if m.TruePositives != 0 || m.FalseNegatives != 1 {
		t.Fatalf("POTENTIAL counted as a detection: %+v", m)
	}
}
