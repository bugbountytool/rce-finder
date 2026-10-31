package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

func TestTableWriterTruncatesLongHumanOutput(t *testing.T) {
	var out bytes.Buffer
	w := NewTableWriter(&out)
	long := strings.Repeat("x", 100)
	if err := w.Write(engine.Result{Status: engine.StatusConfirmed, Severity: "critical", TemplateID: "test", Target: long, Detail: long}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "...") || strings.Contains(got, long) {
		t.Fatalf("table output was not compacted: %q", got)
	}
}

func TestTableWriterCountsDryRunsSeparately(t *testing.T) {
	var out bytes.Buffer
	w := NewTableWriter(&out)
	if err := w.Write(engine.Result{Status: engine.StatusDryRun}); err != nil {
		t.Fatal(err)
	}
	if got := w.Summary(); !strings.Contains(got, "1 dry runs") || strings.Contains(got, "1 not vulnerable") {
		t.Fatalf("Summary() = %q", got)
	}
}
