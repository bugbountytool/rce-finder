package report

import (
	"strings"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

// ShouldFail implements an opt-in CI policy. Potential, inconclusive, errors,
// fingerprints, and negative tests never fail CI merely by being present.
func ShouldFail(results []engine.Result, classification, minimumSeverity string) bool {
	allowed := engine.StatusConfirmed
	if strings.EqualFold(classification, "high-confidence") || strings.EqualFold(classification, "high_confidence") {
		allowed = engine.StatusHighConfidence
	} else if !strings.EqualFold(classification, "confirmed") {
		return false
	}
	minimum := severityRank(minimumSeverity)
	for _, result := range results {
		status := result.Classification
		if status == "" {
			status = result.Status
		}
		if (status == allowed || allowed == engine.StatusHighConfidence && status == engine.StatusConfirmed) && severityRank(result.Severity) >= minimum {
			return true
		}
	}
	return false
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
