// Package template defines and loads vulnerability check templates.
//
// Every check the scanner can run is declared in YAML, not Go. This keeps
// the detection logic auditable (anyone can read a template and see exactly
// what request it sends and what it treats as proof) and keeps the project
// extensible without touching the core engine. This mirrors how widely
// used, reputable scanners in this space structure their checks.
//
// A template's "proof" is always an out-of-band (OOB) interaction: the
// payload asks the target to make a DNS lookup or HTTP request back to a
// canary the engine controls. A callback is treated as confirmed code
// execution / server-side interpretation. No template in this repository
// should ever rely on a destructive action (file write, reverse shell,
// data exfiltration) as its proof mechanism.
package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity is informational only; it never changes scanning behavior.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// InjectionPoint describes where in the HTTP request the payload is placed.
type InjectionPoint struct {
	// Location is one of: "header", "query", "body", "path".
	Location string `yaml:"location"`
	// Name is the header name or query/body parameter name. Ignored for
	// "path" and "body-raw".
	Name string `yaml:"name"`
}

// Template is a single vulnerability check definition.
type Template struct {
	// SchemaVersion controls compatibility for the declarative template model.
	// Empty means legacy v1 and remains supported during the migration.
	SchemaVersion string   `yaml:"schema_version,omitempty"`
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Severity      Severity `yaml:"severity"`
	References    []string `yaml:"references"`
	Vulnclass     string   `yaml:"vuln_class"` // e.g. "ssti", "deserialization", "el-injection"
	CWEs          []string `yaml:"cwe,omitempty"`
	CVEs          []string `yaml:"cve,omitempty"`
	Technologies  []string `yaml:"technologies,omitempty"`
	// Mode declares the greatest capability this template requires. Accepted
	// values are passive, safe-validation, and advanced-authorized.
	Mode string `yaml:"mode,omitempty"`
	// ConfidenceRequirements documents the evidence required to classify a hit.
	ConfidenceRequirements []string `yaml:"confidence_requirements,omitempty"`
	Remediation            string   `yaml:"remediation,omitempty"`

	// OOBProtocol is "dns" or "http" — which kind of callback counts as a hit.
	OOBProtocol string `yaml:"oob_protocol"`

	Method          string           `yaml:"method"` // GET, POST, etc.
	PathTemplate    string           `yaml:"path"`   // request path, may be plain
	InjectionPoints []InjectionPoint `yaml:"injection_points"`
	// PayloadTemplate contains the literal "{{canary}}" placeholder, which
	// the engine replaces with a unique, per-probe canary value before
	// sending. Never commit a template whose payload does anything beyond
	// triggering an OOB callback.
	PayloadTemplate string `yaml:"payload"`

	BodyContentType string `yaml:"body_content_type,omitempty"`

	// TimeoutSeconds is how long to wait for an OOB callback before this
	// probe is marked NOT_VULNERABLE rather than CONFIRMED.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// Validate checks structural correctness and enforces the "OOB-only proof"
// safety rule — a template that doesn't reference {{canary}} cannot produce
// a verifiable, non-destructive result, so it's rejected at load time.
func (t *Template) Validate() error {
	if t.SchemaVersion != "" && t.SchemaVersion != "rce-finder/v2" {
		return fmt.Errorf("template %s: unsupported schema_version %q", t.ID, t.SchemaVersion)
	}
	if t.ID == "" {
		return fmt.Errorf("template missing id")
	}
	if t.Name == "" {
		return fmt.Errorf("template %s missing name", t.ID)
	}
	if t.OOBProtocol != "dns" && t.OOBProtocol != "http" {
		return fmt.Errorf("template %s: oob_protocol must be 'dns' or 'http', got %q", t.ID, t.OOBProtocol)
	}
	if t.Mode == "" {
		t.Mode = "safe-validation"
	}
	if t.Mode != "passive" && t.Mode != "safe-validation" && t.Mode != "advanced-authorized" {
		return fmt.Errorf("template %s: unknown mode %q", t.ID, t.Mode)
	}
	for _, cwe := range t.CWEs {
		if !strings.HasPrefix(cwe, "CWE-") {
			return fmt.Errorf("template %s: invalid CWE %q", t.ID, cwe)
		}
	}
	for _, cve := range t.CVEs {
		if !strings.HasPrefix(cve, "CVE-") {
			return fmt.Errorf("template %s: invalid CVE %q", t.ID, cve)
		}
	}
	if !strings.Contains(t.PayloadTemplate, "{{canary}}") {
		return fmt.Errorf("template %s: payload must contain {{canary}} placeholder — templates must prove impact via OOB callback, not direct effect", t.ID)
	}
	if len(t.InjectionPoints) == 0 {
		return fmt.Errorf("template %s: must declare at least one injection_point", t.ID)
	}
	for i, ip := range t.InjectionPoints {
		switch ip.Location {
		case "header", "query", "body":
			if ip.Name == "" {
				return fmt.Errorf("template %s: injection_points[%d] of type %q requires a name", t.ID, i, ip.Location)
			}
		case "path":
			// no name required
		default:
			return fmt.Errorf("template %s: injection_points[%d] has unknown location %q", t.ID, i, ip.Location)
		}
	}
	if t.Method == "" {
		t.Method = "GET"
	}
	if t.TimeoutSeconds <= 0 {
		t.TimeoutSeconds = 10
	}
	return nil
}

// Render substitutes the canary token into the payload.
func (t *Template) Render(canary string) string {
	return strings.ReplaceAll(t.PayloadTemplate, "{{canary}}", canary)
}

// LoadDir loads and validates every *.yaml / *.yml file in dir.
func LoadDir(dir string) ([]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading templates dir: %w", err)
	}

	var templates []*Template
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if err := t.Validate(); err != nil {
			return nil, fmt.Errorf("invalid template %s: %w", path, err)
		}
		if prev, ok := seen[t.ID]; ok {
			return nil, fmt.Errorf("duplicate template id %q in %s (already defined in %s)", t.ID, path, prev)
		}
		seen[t.ID] = path
		templates = append(templates, &t)
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found in %s", dir)
	}
	return templates, nil
}
