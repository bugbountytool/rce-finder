package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// WriteFindingJSONL emits one rich finding per line, including the
// source-to-sink flow, root cause, verification basis, and evidence digests.
// Advisory AI text is rendered in a clearly separate field and never merged
// into the classification.
func WriteFindingJSONL(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// WriteFindingMarkdown renders a detailed, human-readable finding report with
// the full source-to-sink path and root cause. This is the investigation view,
// not a scan-statistics table.
func WriteFindingMarkdown(w io.Writer, findings []model.Finding) error {
	if _, err := fmt.Fprint(w, "# Security findings\n\n"); err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "## %s\n\n", f.Title); err != nil {
			return err
		}
		fmt.Fprintf(w, "- **ID:** %s\n", f.ID)
		fmt.Fprintf(w, "- **Status:** %s (%s)\n", f.Status, f.Basis)
		fmt.Fprintf(w, "- **Severity:** %s | **Confidence:** %d\n", f.Severity, f.Confidence.Score)
		fmt.Fprintf(w, "- **Asset:** %s\n", f.Asset)
		if f.Endpoint != "" {
			fmt.Fprintf(w, "- **Endpoint:** %s\n", f.Endpoint)
		}
		if len(f.CWEs) > 0 {
			fmt.Fprintf(w, "- **CWE:** %s\n", strings.Join(f.CWEs, ", "))
		}
		if len(f.CVEs) > 0 {
			fmt.Fprintf(w, "- **CVE:** %s\n", strings.Join(f.CVEs, ", "))
		}
		fmt.Fprintf(w, "- **Why this classification:** %s\n", f.StatusReason)
		if f.Flow != nil {
			fmt.Fprintf(w, "\n### Source-to-sink path\n\n```\n%s\n", f.Flow.Source.Name)
			for _, step := range f.Flow.Steps {
				fmt.Fprintf(w, "  -> [%s] %s %s:%d\n", step.Kind, step.Detail, step.Location.File, step.Location.Line)
			}
			fmt.Fprintf(w, "  -> SINK %s (%s:%d)\n```\n", f.Flow.Sink.Kind, f.Flow.Sink.Location.File, f.Flow.Sink.Location.Line)
			fmt.Fprintf(w, "Reachable: %v\n", f.Flow.Reachable)
		}
		if f.RootCause != nil {
			fmt.Fprintf(w, "\n### Root cause\n\n- **Class:** %s\n- **Basis:** %s\n", f.RootCause.Class, f.RootCause.Basis)
			if f.RootCause.Control != "" {
				fmt.Fprintf(w, "- **Missing/ineffective control:** %s\n", f.RootCause.Control)
			}
			if f.RootCause.Explanation != "" {
				fmt.Fprintf(w, "- **Explanation:** %s\n", f.RootCause.Explanation)
			}
			if f.RootCause.WeakestLink != "" {
				fmt.Fprintf(w, "- **Weakest link (assumption):** %s\n", f.RootCause.WeakestLink)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "\n### Remediation\n\n%s\n", f.Remediation)
		}
		if len(f.References) > 0 {
			fmt.Fprintf(w, "\n### References\n\n")
			for _, r := range f.References {
				fmt.Fprintf(w, "- %s\n", r)
			}
		}
		if len(f.Evidence) > 0 {
			fmt.Fprintf(w, "\n### Evidence (digests)\n\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "- %s: `%s`\n", e.Kind, e.Digest)
			}
		}
		if f.AIAdvisory != nil {
			fmt.Fprintf(w, "\n### AI advisory (advisory only — not evidence)\n\n")
			fmt.Fprintf(w, "_Model: %s. This text is advisory and did not affect the classification._\n\n", f.AIAdvisory.ModelID)
			if f.AIAdvisory.Explanation != "" {
				fmt.Fprintf(w, "%s\n", f.AIAdvisory.Explanation)
			}
			if f.AIAdvisory.Remediation != "" {
				fmt.Fprintf(w, "\nSuggested remediation: %s\n", f.AIAdvisory.Remediation)
			}
		}
		fmt.Fprintln(w, "\n---")
	}
	return nil
}
