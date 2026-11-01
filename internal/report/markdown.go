package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

// WriteMarkdown creates a portable, redacted summary suitable for a finding
// review. It intentionally does not embed request bodies, headers, or canaries.
func WriteMarkdown(w io.Writer, results []engine.Result) error {
	if _, err := fmt.Fprintln(w, "# RCE Finder scan report\n\n| Status | Severity | Template | Target | Detail |\n|---|---|---|---|---|"); err != nil {
		return err
	}
	for _, result := range results {
		result = sanitized(result)
		detail := result.Detail
		if result.Canary != "" {
			detail = strings.ReplaceAll(detail, result.Canary, "[redacted-canary]")
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", esc(result.Status), esc(result.Severity), esc(result.TemplateID), esc(result.Target), esc(detail)); err != nil {
			return err
		}
	}
	return nil
}

func esc(value any) string {
	return strings.ReplaceAll(strings.ReplaceAll(fmt.Sprint(value), "|", "\\|"), "\n", " ")
}
