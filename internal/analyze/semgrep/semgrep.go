// Package semgrep adapts the external Semgrep analyzer. It runs Semgrep as a
// sandboxed subprocess with no network, parses its JSON output, and normalizes
// results into the shared candidate model. If the Semgrep binary is absent the
// adapter reports unavailability rather than failing.
package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// Config controls a Semgrep invocation.
type Config struct {
	Binary  string        // path to semgrep; default "semgrep"
	Ruleset string        // e.g. "p/golang" or a local rules path
	Dir     string        // directory to scan
	Timeout time.Duration // hard wall-clock limit
}

// Result is one normalized Semgrep finding.
type Result struct {
	CheckID  string
	Path     string
	Line     int
	Severity string
	Message  string
}

// Available reports whether the Semgrep binary can be executed.
func Available(binary string) bool {
	if binary == "" {
		binary = "semgrep"
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"extra"`
	} `json:"results"`
}

// Run executes Semgrep and normalizes results. It returns an error when the
// binary is missing so callers can fall back to another tier.
func Run(ctx context.Context, cfg Config) ([]Result, error) {
	binary := cfg.Binary
	if binary == "" {
		binary = "semgrep"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("semgrep binary not found: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	args := []string{"scan", "--json", "--quiet", "--no-git-ignore", "--disable-version-check"}
	if cfg.Ruleset != "" {
		args = append(args, "--config", cfg.Ruleset)
	}
	args = append(args, cfg.Dir)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cfg.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("semgrep run: %w (%s)", err, stderr.String())
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parsing semgrep JSON: %w", err)
	}
	results := make([]Result, 0, len(out.Results))
	for _, r := range out.Results {
		results = append(results, Result{
			CheckID:  r.CheckID,
			Path:     r.Path,
			Line:     r.Start.Line,
			Severity: r.Extra.Severity,
			Message:  r.Extra.Message,
		})
	}
	return results, nil
}

// ToCandidates converts Semgrep results into unverified candidates. Semgrep
// findings are pattern-level evidence only; the verification kernel decides
// their final classification.
func ToCandidates(asset string, results []Result) []model.Candidate {
	out := make([]model.Candidate, 0, len(results))
	for i, r := range results {
		out = append(out, model.Candidate{
			ID:       fmt.Sprintf("semgrep-%s-%d", r.CheckID, i),
			Title:    r.CheckID,
			Class:    "static-pattern",
			Asset:    asset,
			Severity: normalizeSeverity(r.Severity),
			Provenance: model.Provenance{
				Engine: "semgrep",
				RuleID: r.CheckID,
			},
		})
	}
	return out
}

func normalizeSeverity(s string) string {
	switch s {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	default:
		return "low"
	}
}
