package correlate

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/analyze/gosast"
	"github.com/bugbountytool/rce-finder/internal/model"
)

func staticFinding(complete bool) gosast.Finding {
	return gosast.Finding{
		RuleID: "go-command-injection", Class: "command-injection", CWE: "CWE-78",
		SourceName: "FormValue", Complete: complete,
	}
}

func TestStaticOnlyFinding(t *testing.T) {
	e := New(nil)
	out := e.Correlate([]gosast.Finding{staticFinding(true)}, nil)
	if len(out) != 1 || out[0].Strength != "static-only" || out[0].Runtime != nil {
		t.Fatalf("static-only = %+v", out)
	}
}

func TestCorrelatedWithRuntimeObservation(t *testing.T) {
	e := New(nil)
	obs := []RuntimeObservation{{Endpoint: "POST /vuln", Parameter: "cmd", Status: model.StatusHighConfidence, ProbeID: "p1"}}
	out := e.Correlate([]gosast.Finding{staticFinding(true)}, obs)
	if len(out) != 1 || out[0].Strength != "correlated" || out[0].Runtime == nil {
		t.Fatalf("correlated = %+v", out)
	}
}

func TestConfirmedRuntimeUpgradesStrength(t *testing.T) {
	e := New(nil)
	obs := []RuntimeObservation{{Endpoint: "POST /vuln", Parameter: "cmd", Status: model.StatusConfirmed}}
	out := e.Correlate([]gosast.Finding{staticFinding(true)}, obs)
	if out[0].Strength != "confirmed" {
		t.Fatalf("strength = %s", out[0].Strength)
	}
}

func TestCandidateCarriesFlowAndEndpoint(t *testing.T) {
	e := New(nil)
	obs := []RuntimeObservation{{Endpoint: "POST /vuln", Parameter: "cmd", Status: model.StatusConfirmed}}
	out := e.Correlate([]gosast.Finding{staticFinding(true)}, obs)
	cand := out[0].ToCandidate("https://example.test")
	if cand.Flow == nil || !cand.Flow.Reachable {
		t.Fatal("candidate missing reachable flow")
	}
	if cand.Endpoint != "POST /vuln" {
		t.Fatalf("endpoint = %s", cand.Endpoint)
	}
	if cand.Class != "command-injection" {
		t.Fatalf("class = %s", cand.Class)
	}
}
