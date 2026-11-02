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
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bugbountytool/rce-finder/internal/requestbody"
)

// Severity is informational only; it never changes scanning behavior.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Prerequisites struct {
	RequiredTechnologies         []string `yaml:"required_technologies,omitempty"`
	MinimumFingerprintConfidence int      `yaml:"minimum_fingerprint_confidence,omitempty"`
	AllowedMethods               []string `yaml:"allowed_methods,omitempty"`
	AllowedContentTypes          []string `yaml:"allowed_content_types,omitempty"`
	RequiredMode                 string   `yaml:"required_mode,omitempty"`
}

type Matcher struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

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
	SchemaVersion string        `yaml:"schema_version,omitempty"`
	ID            string        `yaml:"id"`
	Name          string        `yaml:"name"`
	Severity      Severity      `yaml:"severity"`
	References    []string      `yaml:"references"`
	Vulnclass     string        `yaml:"vuln_class"` // e.g. "ssti", "deserialization", "el-injection"
	CWEs          []string      `yaml:"cwe,omitempty"`
	CVEs          []string      `yaml:"cve,omitempty"`
	Technologies  []string      `yaml:"technologies,omitempty"`
	Prerequisites Prerequisites `yaml:"prerequisites,omitempty"`
	// Mode declares the capability this template requires. Only passive and
	// safe-validation definitions are supported; advanced templates are rejected.
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

	BodyContentType string              `yaml:"body_content_type,omitempty"`
	BodyFields      []requestbody.Field `yaml:"body_fields,omitempty"`
	// MultipartBoundary is fixed in reviewed templates so request bytes are
	// reproducible. Random per-request boundaries are not currently supported.
	MultipartBoundary string    `yaml:"multipart_boundary,omitempty"`
	Matchers          []Matcher `yaml:"matchers,omitempty"`

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
		// Mode is read-only during validation; callers use EffectiveMode().
	}
	if strings.HasPrefix(t.PathTemplate, "/") || strings.Contains(t.PathTemplate, "..") || strings.Contains(t.PathTemplate, "\\") || strings.ContainsAny(t.PathTemplate, "\r\n") {
		return fmt.Errorf("template %s: path must be relative and cannot contain traversal or control characters", t.ID)
	}
	if t.EffectiveMode() == "passive" {
		return fmt.Errorf("template %s: passive definitions cannot be used for active OOB probes", t.ID)
	}
	if t.EffectiveMode() != "safe-validation" {
		return fmt.Errorf("template %s: unsupported or unsafe mode %q", t.ID, t.EffectiveMode())
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
	switch t.BodyContentType {
	case "", "application/x-www-form-urlencoded", "application/json":
		if len(t.BodyFields) != 0 || t.MultipartBoundary != "" {
			return fmt.Errorf("template %s: body_fields and multipart_boundary require XML or multipart content type", t.ID)
		}
	case "application/xml", "text/xml":
		if len(t.BodyFields) == 0 {
			return fmt.Errorf("template %s: XML requires declared text body_fields", t.ID)
		}
		if t.MultipartBoundary != "" {
			return fmt.Errorf("template %s: multipart_boundary is only valid for multipart bodies", t.ID)
		}
	case "multipart/form-data":
		if len(t.BodyFields) == 0 || t.MultipartBoundary == "" {
			return fmt.Errorf("template %s: multipart requires declared text body_fields and a fixed boundary", t.ID)
		}
	default:
		return fmt.Errorf("template %s: unsupported body_content_type %q", t.ID, t.BodyContentType)
	}
	var bodyInjections int
	for i, ip := range t.InjectionPoints {
		switch ip.Location {
		case "header", "query", "body":
			if ip.Name == "" {
				return fmt.Errorf("template %s: injection_points[%d] of type %q requires a name", t.ID, i, ip.Location)
			}
			if strings.ContainsAny(ip.Name, "\r\n\x00") || ip.Location == "header" && !validHeaderName(ip.Name) {
				return fmt.Errorf("template %s: injection point %q has an invalid name", t.ID, ip.Name)
			}
			if ip.Location == "header" && (strings.EqualFold(ip.Name, "Host") || strings.EqualFold(ip.Name, "Content-Length") || strings.EqualFold(ip.Name, "Cookie") || strings.EqualFold(ip.Name, "Authorization")) {
				return fmt.Errorf("template %s: sensitive or transport header %q cannot be an injection point", t.ID, ip.Name)
			}
		case "path":
			if !strings.Contains(t.PathTemplate, "{{inject}}") {
				return fmt.Errorf("template %s: path injection requires a {{inject}} placeholder", t.ID)
			}
		default:
			return fmt.Errorf("template %s: injection_points[%d] has unknown location %q", t.ID, i, ip.Location)
		}
		if ip.Location == "body" {
			bodyInjections++
		}
	}
	if len(t.BodyFields) > 0 {
		if bodyInjections == 0 {
			return fmt.Errorf("template %s: typed body requires a body injection point", t.ID)
		}
		declared := make(map[string]bool, len(t.BodyFields))
		for _, field := range t.BodyFields {
			declared[field.Name] = true
		}
		for _, ip := range t.InjectionPoints {
			if ip.Location == "body" && !declared[ip.Name] {
				return fmt.Errorf("template %s: body injection %q is not a declared text field", t.ID, ip.Name)
			}
		}
	}
	if t.Method == "" {
		t.Method = http.MethodGet
	}
	switch t.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
	default:
		return fmt.Errorf("template %s: unsupported HTTP method %q", t.ID, t.Method)
	}
	if len(t.Prerequisites.AllowedMethods) > 0 && !containsFold(t.Prerequisites.AllowedMethods, t.Method) {
		return fmt.Errorf("template %s: method %q is not allowed by prerequisites", t.ID, t.Method)
	}
	contentType := t.BodyContentType
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	if len(t.Prerequisites.AllowedContentTypes) > 0 && !containsFold(t.Prerequisites.AllowedContentTypes, contentType) {
		return fmt.Errorf("template %s: content type %q is not allowed by prerequisites", t.ID, contentType)
	}
	for _, matcher := range t.Matchers {
		if matcher.Type != "word" && matcher.Type != "status" || matcher.Value == "" {
			return fmt.Errorf("template %s: matcher must be a nonempty status or word matcher", t.ID)
		}
	}
	if len(t.InjectionPoints) > 32 {
		return fmt.Errorf("template %s: exceeds 32 injection points", t.ID)
	}
	if len(t.PayloadTemplate) > 64<<10 {
		return fmt.Errorf("template %s: payload exceeds 64 KiB", t.ID)
	}
	if t.TimeoutSeconds < 0 || t.TimeoutSeconds > 120 {
		return fmt.Errorf("template %s: timeout_seconds must be between 1 and 120", t.ID)
	}
	if t.Prerequisites.MinimumFingerprintConfidence < 0 || t.Prerequisites.MinimumFingerprintConfidence > 100 {
		return fmt.Errorf("template %s: minimum fingerprint confidence must be between 0 and 100", t.ID)
	}
	if t.Prerequisites.RequiredMode != "" && t.Prerequisites.RequiredMode != t.EffectiveMode() {
		return fmt.Errorf("template %s: prerequisite mode must match declared mode", t.ID)
	}
	return nil
}

func validHeaderName(name string) bool {
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return name != ""
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// Render substitutes the canary token into the payload.
func (t *Template) Render(canary string) string {
	return strings.ReplaceAll(t.PayloadTemplate, "{{canary}}", canary)
}

// EffectiveMode returns the declared capability mode, defaulting to
// safe-validation when unset. It never mutates the template.
func (t *Template) EffectiveMode() string {
	if t.Mode == "" {
		return "safe-validation"
	}
	return t.Mode
}

// EffectiveTimeout returns the OOB wait in seconds, defaulting to 10 when
// unset or non-positive. It never mutates the template.
func (t *Template) EffectiveTimeout() int {
	if t.TimeoutSeconds <= 0 {
		return 10
	}
	return t.TimeoutSeconds
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
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&t); err != nil {
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
