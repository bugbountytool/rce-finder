package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

func TestWriteSARIFExportsFindingsNotDryRuns(t *testing.T) {
	var out bytes.Buffer
	err := WriteSARIF(&out, []engine.Result{
		{Status: engine.StatusConfirmed, TemplateID: "test", Name: "Test", Target: "https://example.test", Detail: "callback", Severity: "high"},
		{Status: engine.StatusDryRun, TemplateID: "dry", Name: "Dry", Target: "https://example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"version":"2.1.0"`) || !strings.Contains(got, `"ruleId":"test"`) || strings.Contains(got, `"ruleId":"dry"`) {
		t.Fatalf("unexpected SARIF: %s", got)
	}
}
