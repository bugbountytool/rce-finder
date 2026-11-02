package apisec

import (
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/model"
	"github.com/bugbountytool/rce-finder/internal/verify"
)

// ToObservation maps an API finding to a verification observation. A
// reproduced differential is strong evidence; a single differential is weak.
func (f Finding) ToObservation() verify.Observation {
	if f.Differential {
		return verify.Observation{
			Kind:           verify.ObsDifferential,
			Repeated:       f.Reproduced,
			ControlMatched: true, // BOLA/BFLA compare against a privileged control
			Note:           f.Detail,
		}
	}
	return verify.Observation{Kind: verify.ObsErrorSig, Note: f.Detail}
}

// ToCandidate converts an API finding into an unverified candidate.
func (f Finding) ToCandidate(asset string) model.Candidate {
	return model.Candidate{
		ID:       fmt.Sprintf("%s-%s-%s-%s", f.Check, f.Op.Method, f.Op.Path, f.Property),
		Title:    string(f.Check) + " on " + f.Op.Method + " " + f.Op.Path,
		Class:    string(f.Check),
		CWEs:     []string{f.CWE},
		Asset:    asset,
		Endpoint: f.Op.Method + " " + f.Op.Path,
		Severity: severityFor(f.Check),
		Provenance: model.Provenance{
			Engine: "apisec",
			RuleID: string(f.Check),
		},
	}
}

func severityFor(c CheckID) string {
	switch c {
	case CheckBOLA, CheckBFLA:
		return "high"
	case CheckMassAssignment:
		return "high"
	case CheckExcessiveExposure:
		return "medium"
	default:
		return "low"
	}
}
