package report

import (
	"strings"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/evidence"
	"github.com/bugbountytool/rce-finder/internal/model"
)

func nowForTest() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func richFinding() model.Finding {
	return model.Finding{
		ID: "f1", Title: "Command injection in /vuln", Class: "command-injection",
		CWEs: []string{"CWE-78"}, Asset: "https://example.test", Endpoint: "POST /vuln",
		Severity: "critical", Status: model.StatusConfirmed, Basis: model.BasisCorrelated,
		StatusReason: "reproducible differential plus reachable flow",
		Confidence:   model.Confidence{Score: 100},
		Flow: &model.Flow{
			Source:    model.Source{Kind: "http", Name: "FormValue", Location: model.Location{File: "main.go", Line: 15}},
			Sink:      model.Sink{Kind: "exec", Location: model.Location{File: "main.go", Line: 16}},
			Reachable: true,
			Steps:     []model.FlowStep{{Kind: "call", Location: model.Location{File: "main.go", Line: 16}}},
		},
		RootCause: &model.RootCause{Class: model.ControlMissing, Basis: "source", Control: "input validation", WeakestLink: "assumes FormValue is attacker-controlled"},
		Evidence:  []evidence.Record{evidence.New("observation", "f1", nowForTest(), map[string]string{"kind": "oob"})},
		Remediation: "Do not pass untrusted input to exec",
		References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
		AIAdvisory:  &model.AIAdvisory{Advisory: true, Explanation: "AI explanation", ModelID: "m1"},
	}
}

func TestWriteFindingMarkdownIncludesFlowRootCauseAndAdvisory(t *testing.T) {
	var b strings.Builder
	if err := WriteFindingMarkdown(&b, []model.Finding{richFinding()}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"CONFIRMED (correlated)", "Source-to-sink path", "FormValue", "exec",
		"Root cause", "control_missing", "Weakest link", "Remediation",
		"AI advisory", "advisory only", "Evidence (digests)", "CWE-78",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestWriteFindingJSONLRoundTrips(t *testing.T) {
	var b strings.Builder
	if err := WriteFindingJSONL(&b, []model.Finding{richFinding()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\"status\":\"CONFIRMED\"") {
		t.Fatal("JSONL missing status")
	}
	if !strings.Contains(b.String(), "\"advisory\":true") {
		t.Fatal("JSONL missing advisory marker")
	}
}
