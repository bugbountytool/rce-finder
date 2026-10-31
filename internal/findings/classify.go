// Package findings converts evidence quality into intentionally conservative
// finding classifications.
package findings

type Status string

const (
	Confirmed      Status = "CONFIRMED"
	HighConfidence Status = "HIGH_CONFIDENCE"
	Potential      Status = "POTENTIAL"
	NotVulnerable  Status = "NOT_VULNERABLE"
	Inconclusive   Status = "INCONCLUSIVE"
	Error          Status = "ERROR"
	Skipped        Status = "SKIPPED"
	Blocked        Status = "BLOCKED"
)

type Evidence struct {
	CorrelatedOOB      bool
	ProtocolMatches    bool
	ProbeIDMatches     bool
	StrongResponseHint bool
	CompletedNegative  bool
	Ambiguous          bool
}

func Classify(e Evidence) Status {
	if e.CorrelatedOOB && e.ProtocolMatches && e.ProbeIDMatches {
		return Confirmed
	}
	if e.StrongResponseHint && !e.Ambiguous {
		return HighConfidence
	}
	if e.CompletedNegative {
		return NotVulnerable
	}
	if e.Ambiguous {
		return Inconclusive
	}
	return Potential
}
