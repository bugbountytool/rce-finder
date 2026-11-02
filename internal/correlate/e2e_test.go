package correlate_test

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/analyze/gosast"
	"github.com/bugbountytool/rce-finder/internal/correlate"
	"github.com/bugbountytool/rce-finder/internal/model"
	"github.com/bugbountytool/rce-finder/internal/verify"
)

// End-to-end: a complete static flow correlated with a dynamically confirmed
// endpoint must yield CONFIRMED via the verification kernel, with basis
// "correlated". A static flow alone must NOT reach CONFIRMED.
func TestStaticPlusDynamicYieldsConfirmed(t *testing.T) {
	e := correlate.New(nil)
	sf := gosast.Finding{RuleID: "go-command-injection", Class: "command-injection", CWE: "CWE-78", SourceName: "FormValue", Complete: true}

	// static only
	staticOnly := e.Correlate([]gosast.Finding{sf}, nil)[0]
	f, err := verify.New().Verify(staticOnly.ToCandidate("https://example.test"), []verify.Observation{
		{Kind: verify.ObsStaticFlow, CompleteFlow: true, Reachable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status == model.StatusConfirmed {
		t.Fatal("static-only flow reached CONFIRMED; must be HIGH_CONFIDENCE at most")
	}
	if f.Status != model.StatusHighConfidence || f.Basis != model.BasisSource {
		t.Fatalf("static-only = %s/%s", f.Status, f.Basis)
	}

	// static + dynamic differential (repeated, controlled) => correlated CONFIRMED
	obs := []correlate.RuntimeObservation{{Endpoint: "POST /vuln", Parameter: "cmd", Status: model.StatusConfirmed}}
	cor := e.Correlate([]gosast.Finding{sf}, obs)[0]
	f2, err := verify.New().Verify(cor.ToCandidate("https://example.test"), []verify.Observation{
		{Kind: verify.ObsStaticFlow, CompleteFlow: true, Reachable: true},
		{Kind: verify.ObsDifferential, Repeated: true, ControlMatched: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f2.Status != model.StatusConfirmed || f2.Basis != model.BasisCorrelated {
		t.Fatalf("static+dynamic = %s/%s, want CONFIRMED/correlated", f2.Status, f2.Basis)
	}
}
