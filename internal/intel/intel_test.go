package intel

import (
	"testing"
)

func TestAssessNeverConfirmsFromIntelligence(t *testing.T) {
	a := Advisory{ID: "OSV-1", Package: "x", Fixed: "2.0.0"}
	cases := []struct {
		reachable bool
		threat    ThreatContext
		wantTier  Tier
		maxConf   float64
	}{
		{false, ThreatContext{}, TierVersionOnly, 0.4},
		{true, ThreatContext{}, TierReachable, 0.7},
		{true, ThreatContext{InKEV: true, EPSS: 0.9}, TierThreatEnriched, 0.75},
		{false, ThreatContext{InKEV: true}, TierThreatEnriched, 0.55},
	}
	for _, tc := range cases {
		as := Assess(a, tc.reachable, tc.threat)
		if as.Tier != tc.wantTier {
			t.Errorf("tier = %d want %d", as.Tier, tc.wantTier)
		}
		if as.Confidence > tc.maxConf {
			t.Errorf("confidence %f exceeds cap %f", as.Confidence, tc.maxConf)
		}
		if !as.NeverConfirmed() {
			t.Error("intelligence assessment must never be a confirmation")
		}
		if as.Statement == "" {
			t.Error("assessment missing explanatory statement")
		}
	}
}

func TestEPSSIsNotMultipliedIntoExploitProbability(t *testing.T) {
	// KEV+EPSS raise prioritization, not a local exploit probability. Two
	// assessments differing only in EPSS must have the same confidence cap.
	a := Advisory{ID: "x"}
	low := Assess(a, true, ThreatContext{EPSS: 0.01})
	high := Assess(a, true, ThreatContext{EPSS: 0.99})
	if low.Confidence != high.Confidence {
		t.Fatalf("EPSS changed local confidence: %f vs %f", low.Confidence, high.Confidence)
	}
}
