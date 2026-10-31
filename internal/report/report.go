// Package report formats scan results for humans (CLI table) and machines
// (JSON lines, for CI pipelines and bug bounty tooling integrations).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

// JSONWriter writes one JSON object per result (JSON Lines format), suitable
// for piping into jq or other tooling.
type JSONWriter struct {
	w   io.Writer
	enc *json.Encoder
}

func NewJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{w: w, enc: json.NewEncoder(w)}
}

func (j *JSONWriter) Write(r engine.Result) error {
	return j.enc.Encode(r)
}

// TableWriter prints a human-readable, aligned summary table as results
// arrive, plus a final counts line.
type TableWriter struct {
	tw        *tabwriter.Writer
	confirmed int
	clean     int
	dryRuns   int
	skipped   int
	blocked   int
	errored   int
	header    bool
}

func NewTableWriter(w io.Writer) *TableWriter {
	return &TableWriter{tw: tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)}
}

func (t *TableWriter) Write(r engine.Result) error {
	if !t.header {
		fmt.Fprintln(t.tw, "STATUS\tSEVERITY\tTEMPLATE\tTARGET\tDETAIL")
		t.header = true
	}
	switch r.Status {
	case engine.StatusConfirmed:
		t.confirmed++
	case engine.StatusNotVulnerable:
		t.clean++
	case engine.StatusDryRun:
		t.dryRuns++
	case engine.StatusSkipped:
		t.skipped++
	case engine.StatusBlocked:
		t.blocked++
	case engine.StatusError:
		t.errored++
	}
	fmt.Fprintf(t.tw, "%s\t%s\t%s\t%s\t%s\n",
		r.Status,
		r.Severity,
		r.TemplateID,
		truncate(r.Target, 42),
		truncate(r.Detail, 72),
	)
	return t.tw.Flush()
}

func (t *TableWriter) Summary() string {
	return fmt.Sprintf("\nScan complete: %d confirmed, %d not vulnerable, %d dry runs, %d skipped, %d blocked, %d errors\n", t.confirmed, t.clean, t.dryRuns, t.skipped, t.blocked, t.errored)
}

// truncate keeps terminal tables readable. JSON output always retains the
// complete target and detail strings for automation or forensic review.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}
