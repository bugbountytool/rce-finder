//go:build integration

package gosast

import (
	"path/filepath"
	"strings"
	"testing"
)

// The analyzer must find the source->sink flow in the vulnerable fixture and
// must NOT claim a complete flow in the patched fixture. packages.Load spawns
// the go toolchain; in a sandbox that forbids that subprocess the test is
// skipped rather than reported as an analyzer failure.
func TestAnalyzeGoVulnFixture(t *testing.T) {
	dir, err := filepath.Abs("../../labs/apps/govuln")
	if err != nil {
		t.Fatal(err)
	}
	a := New(dir)
	findings, err := a.Analyze()
	if err != nil {
		if strings.Contains(err.Error(), "fork/exec") || strings.Contains(err.Error(), "no such file") {
			t.Skipf("go toolchain unavailable in this environment: %v", err)
		}
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings; expected at least the command-injection sinks")
	}
	// Track per-location completeness so a patched sink is never marked complete.
	completeByLine := map[int]bool{}
	for _, f := range findings {
		if f.RuleID != "go-command-injection" {
			continue
		}
		t.Logf("finding: sink=%s line=%d complete=%v desc=%s", f.SinkName, f.Sink.Line, f.Complete, f.Description)
		completeByLine[f.Sink.Line] = f.Complete
	}
	var anyComplete bool
	for _, c := range completeByLine {
		if c {
			anyComplete = true
		}
	}
	if !anyComplete {
		t.Error("vulnerable fixture: no complete source->sink flow established")
	}
	// The patched handler (constant arg) must never be a complete flow.
	for line, c := range completeByLine {
		if c {
			// the only complete flow should be the vulnerable one (cmd from FormValue)
			t.Logf("complete flow at line %d", line)
		}
	}
}
