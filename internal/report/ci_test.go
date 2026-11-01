package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/evidence"
)

func TestCIPolicyIgnoresWeakAndOperationalResults(t *testing.T) {
	if ShouldFail([]engine.Result{{Status: engine.StatusPotential, Severity: "critical"}, {Status: engine.StatusInconclusive, Severity: "critical"}, {Status: engine.StatusError, Severity: "critical"}}, "confirmed", "high") {
		t.Fatal("weak/operational results failed CI")
	}
	if !ShouldFail([]engine.Result{{Classification: engine.StatusConfirmed, Severity: "high"}}, "confirmed", "high") {
		t.Fatal("confirmed high severity did not fail CI")
	}
	if ShouldFail([]engine.Result{{Classification: engine.StatusConfirmed, Severity: "medium"}}, "confirmed", "critical") {
		t.Fatal("finding below threshold failed CI")
	}
	if !ShouldFail([]engine.Result{{Classification: engine.StatusHighConfidence, Severity: "critical"}}, "high-confidence", "critical") {
		t.Fatal("high-confidence policy did not fail")
	}
}

func TestAllFormatsRedactRequestSecretsAndCanaries(t *testing.T) {
	const secret = "authorization-cookie-token-secret"
	const canary = "secret-canary.oob.test"
	result := engine.Result{ScanID: "scan", JobID: "job", ProbeID: "probe", Target: "https://example.test/", TemplateID: "safe", Status: engine.StatusConfirmed, Classification: engine.StatusConfirmed, Severity: "high", Detail: "matching callback", Confidence: engine.Confidence{Score: 100}, Evidence: []evidence.Record{evidence.New(evidence.KindRequest, "probe", time.Now(), map[string]string{"method": "GET", "url": "https://example.test/?q=[redacted]"})}}
	var outputs = map[string]func(*bytes.Buffer) error{
		"markdown": func(b *bytes.Buffer) error { return WriteMarkdown(b, []engine.Result{result}) },
		"sarif":    func(b *bytes.Buffer) error { return WriteSARIF(b, []engine.Result{result}) },
		"html":     func(b *bytes.Buffer) error { return WriteHTML(b, []engine.Result{result}) },
		"csv":      func(b *bytes.Buffer) error { return WriteCSV(b, []engine.Result{result}) },
		"json":     func(b *bytes.Buffer) error { return json.NewEncoder(b).Encode(result) },
	}
	for name, write := range outputs {
		var buf bytes.Buffer
		if err := write(&buf); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), canary) {
			t.Errorf("%s leaked secret or canary: %s", name, buf.String())
		}
	}
}
