package verify

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/model"
)

func candidate() model.Candidate {
	return model.Candidate{ID: "c1", Title: "test", Class: "rce", Asset: "https://example.test"}
}

func TestOOBCorrelatedIsConfirmed(t *testing.T) {
	k := New()
	f, err := k.Verify(candidate(), []Observation{
		{Kind: ObsOOBCorrelated, ProtocolMatches: true, ProbeIDMatches: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusConfirmed || f.Basis != model.BasisDynamic {
		t.Fatalf("status=%s basis=%s", f.Status, f.Basis)
	}
}

func TestOOBWithoutExactMatchIsNotConfirmed(t *testing.T) {
	k := New()
	for _, o := range []Observation{
		{Kind: ObsOOBCorrelated, ProtocolMatches: true, ProbeIDMatches: false},
		{Kind: ObsOOBCorrelated, ProtocolMatches: false, ProbeIDMatches: true},
	} {
		f, _ := k.Verify(candidate(), []Observation{o})
		if f.Status == model.StatusConfirmed {
			t.Fatalf("inexact OOB was confirmed: %+v", o)
		}
	}
}

// The core invariant: no combination of weak signals can ever reach CONFIRMED.
func TestWeakSignalsNeverBecomeConfirmed(t *testing.T) {
	k := New()
	weak := []Observation{
		{Kind: ObsVersionMatch},
		{Kind: ObsThreatIntel},
		{Kind: ObsFingerprint},
		{Kind: ObsAIAdvisory},
		{Kind: ObsErrorSig},
		{Kind: ObsStaticPattern},
	}
	f, err := k.Verify(candidate(), weak)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status == model.StatusConfirmed || f.Status == model.StatusHighConfidence {
		t.Fatalf("weak signals produced %s", f.Status)
	}
}

func TestVersionMatchAloneIsApplicabilityOnly(t *testing.T) {
	k := New()
	f, err := k.Verify(candidate(), []Observation{{Kind: ObsVersionMatch}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusInconclusive || f.Basis != model.BasisApplicabil {
		t.Fatalf("version match produced %s/%s", f.Status, f.Basis)
	}
}

func TestAIAdvisoryAloneIsInconclusive(t *testing.T) {
	k := New()
	f, _ := k.Verify(candidate(), []Observation{{Kind: ObsAIAdvisory}})
	if f.Status != model.StatusInconclusive {
		t.Fatalf("AI advisory produced %s", f.Status)
	}
}

func TestRepeatedDifferentialIsHighConfidence(t *testing.T) {
	k := New()
	f, err := k.Verify(candidate(), []Observation{
		{Kind: ObsDifferential, Repeated: true, ControlMatched: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusHighConfidence || f.Basis != model.BasisDynamic {
		t.Fatalf("strong differential produced %s/%s", f.Status, f.Basis)
	}
}

func TestCompleteReachableStaticFlowIsHighConfidence(t *testing.T) {
	k := New()
	f, err := k.Verify(candidate(), []Observation{
		{Kind: ObsStaticFlow, CompleteFlow: true, Reachable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusHighConfidence || f.Basis != model.BasisSource {
		t.Fatalf("complete static flow produced %s/%s", f.Status, f.Basis)
	}
}

func TestIncompleteStaticFlowIsOnlyPotential(t *testing.T) {
	k := New()
	f, _ := k.Verify(candidate(), []Observation{{Kind: ObsStaticFlow, CompleteFlow: true, Reachable: false}})
	if f.Status != model.StatusPotential {
		t.Fatalf("unreachable flow produced %s", f.Status)
	}
}

func TestCorrelatedDifferentialPlusFlowIsConfirmed(t *testing.T) {
	k := New()
	f, err := k.Verify(candidate(), []Observation{
		{Kind: ObsDifferential, Repeated: true, ControlMatched: true},
		{Kind: ObsStaticFlow, CompleteFlow: true, Reachable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusConfirmed || f.Basis != model.BasisCorrelated {
		t.Fatalf("correlated evidence produced %s/%s", f.Status, f.Basis)
	}
}

func TestInsufficientEvidenceReturnsError(t *testing.T) {
	k := New()
	if _, err := k.Verify(candidate(), nil); err == nil {
		t.Fatal("empty observations classified without error")
	}
}

func TestNegativeAndBlocked(t *testing.T) {
	k := New()
	f, _ := k.Verify(candidate(), []Observation{{Kind: ObsNegative}})
	if f.Status != model.StatusNotVulnerable {
		t.Fatalf("negative produced %s", f.Status)
	}
	f, _ = k.Verify(candidate(), []Observation{{Kind: ObsBlocked}})
	if f.Status != model.StatusBlocked {
		t.Fatalf("blocked produced %s", f.Status)
	}
}
