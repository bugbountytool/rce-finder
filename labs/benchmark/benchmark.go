// Package benchmark measures detection accuracy against labeled fixtures.
// Given a set of test cases with ground-truth labels and the classifications a
// detection engine produced, it computes precision, recall, false-positive and
// false-negative rates, and — most importantly for this platform — the
// false-confirmation rate (weak evidence reported as CONFIRMED).
//
// No benchmark results are invented: metrics are computed only from the cases
// actually supplied. An empty case set yields an error rather than zeros.
package benchmark

import (
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// Case is one labeled test fixture and the classification an engine gave it.
type Case struct {
	Name string
	// Vulnerable is the ground truth: the fixture actually has the defect.
	Vulnerable bool
	// Status is what the engine reported for this fixture.
	Status model.Status
}

// Metrics are computed detection-accuracy measurements.
type Metrics struct {
	Total int
	// Confusion counts, treating CONFIRMED/HIGH_CONFIDENCE as "reported".
	TruePositives  int
	FalsePositives int
	TrueNegatives  int
	FalseNegatives int

	Precision float64
	Recall    float64
	FalsePositiveRate float64
	FalseNegativeRate float64
	// FalseConfirmationRate is the share of non-vulnerable fixtures reported
	// as CONFIRMED — the metric that matters most for evidence-gated tools.
	FalseConfirmationRate float64
}

// isReported treats only CONFIRMED and HIGH_CONFIDENCE as positive reports;
// POTENTIAL and below are not counted as detections.
func isReported(s model.Status) bool {
	return s == model.StatusConfirmed || s == model.StatusHighConfidence
}

// isConfirmed is stricter: only CONFIRMED.
func isConfirmed(s model.Status) bool { return s == model.StatusConfirmed }

// Compute derives metrics from labeled cases. It errors on an empty set so a
// benchmark can never report invented zeros.
func Compute(cases []Case) (Metrics, error) {
	if len(cases) == 0 {
		return Metrics{}, fmt.Errorf("no benchmark cases supplied")
	}
	var m Metrics
	m.Total = len(cases)
	var actualPositives, actualNegatives int
	for _, c := range cases {
		reported := isReported(c.Status)
		switch {
		case c.Vulnerable && reported:
			m.TruePositives++
		case !c.Vulnerable && reported:
			m.FalsePositives++
		case !c.Vulnerable && !reported:
			m.TrueNegatives++
		case c.Vulnerable && !reported:
			m.FalseNegatives++
		}
		if c.Vulnerable {
			actualPositives++
		} else {
			actualNegatives++
			if isConfirmed(c.Status) {
				m.FalseConfirmationRate++
			}
		}
	}
	if m.TruePositives+m.FalsePositives > 0 {
		m.Precision = float64(m.TruePositives) / float64(m.TruePositives+m.FalsePositives)
	}
	if actualPositives > 0 {
		m.Recall = float64(m.TruePositives) / float64(actualPositives)
		m.FalseNegativeRate = float64(m.FalseNegatives) / float64(actualPositives)
	}
	if actualNegatives > 0 {
		m.FalsePositiveRate = float64(m.FalsePositives) / float64(actualNegatives)
		m.FalseConfirmationRate = m.FalseConfirmationRate / float64(actualNegatives)
	}
	return m, nil
}
