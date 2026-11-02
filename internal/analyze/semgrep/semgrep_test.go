package semgrep

import (
	"testing"
)

func TestToCandidatesArePatternLevel(t *testing.T) {
	results := []Result{
		{CheckID: "go.lang.security.exec", Path: "main.go", Line: 16, Severity: "ERROR", Message: "exec"},
		{CheckID: "go.lang.security.sql", Path: "db.go", Line: 5, Severity: "WARNING"},
	}
	cands := ToCandidates("https://example.test", results)
	if len(cands) != 2 {
		t.Fatalf("candidates = %d", len(cands))
	}
	if cands[0].Class != "static-pattern" {
		t.Fatalf("class = %s; Semgrep findings must stay pattern-level", cands[0].Class)
	}
	if cands[0].Severity != "high" || cands[1].Severity != "medium" {
		t.Fatalf("severity normalization wrong: %s %s", cands[0].Severity, cands[1].Severity)
	}
	if cands[0].Provenance.Engine != "semgrep" {
		t.Fatalf("provenance = %+v", cands[0].Provenance)
	}
}

func TestAvailableHandlesMissingBinary(t *testing.T) {
	if Available("definitely-not-a-real-semgrep-binary-xyz") {
		t.Fatal("reported a nonexistent binary as available")
	}
}
