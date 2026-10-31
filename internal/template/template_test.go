package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTemplate() Template {
	return Template{
		ID: "valid", Name: "Valid", OOBProtocol: "dns",
		PayloadTemplate: "${jndi:ldap://{{canary}}/a}",
		InjectionPoints: []InjectionPoint{{Location: "query", Name: "q"}},
	}
}

func TestValidateAcceptsValidTemplateAndDefaults(t *testing.T) {
	tmpl := validTemplate()
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if tmpl.Method != "GET" || tmpl.TimeoutSeconds != 10 {
		t.Fatalf("defaults = method %q timeout %d", tmpl.Method, tmpl.TimeoutSeconds)
	}
	if got := tmpl.Render("abc.oob.test"); !strings.Contains(got, "abc.oob.test") {
		t.Fatalf("Render() = %q, missing canary", got)
	}
}

func TestValidateRejectsUnsafeOrMalformedStructure(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Template)
	}{
		{"missing ID", func(v *Template) { v.ID = "" }},
		{"invalid protocol", func(v *Template) { v.OOBProtocol = "ldap" }},
		{"missing canary", func(v *Template) { v.PayloadTemplate = "literal" }},
		{"no injection points", func(v *Template) { v.InjectionPoints = nil }},
		{"unnamed header", func(v *Template) { v.InjectionPoints = []InjectionPoint{{Location: "header"}} }},
		{"unknown location", func(v *Template) { v.InjectionPoints = []InjectionPoint{{Location: "cookie", Name: "x"}} }},
		{"unknown mode", func(v *Template) { v.Mode = "unsafe" }},
		{"invalid CWE", func(v *Template) { v.CWEs = []string{"78"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := validTemplate()
			tc.mutate(&tmpl)
			if err := tmpl.Validate(); err == nil {
				t.Fatal("Validate() succeeded, want error")
			}
		})
	}
}

func TestLoadDirRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	data := "id: duplicate\nname: Example\noob_protocol: dns\npayload: '{{canary}}'\ninjection_points:\n  - location: query\n    name: q\n"
	for _, name := range []string{"a.yaml", "b.yml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate template id") {
		t.Fatalf("LoadDir() error = %v, want duplicate-ID error", err)
	}
}

func TestValidateAcceptsV2Metadata(t *testing.T) {
	tmpl := validTemplate()
	tmpl.SchemaVersion = "rce-finder/v2"
	tmpl.CWEs = []string{"CWE-78"}
	tmpl.CVEs = []string{"CVE-2024-1234"}
	tmpl.Technologies = []string{"java"}
	tmpl.Mode = "safe-validation"
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("v2 template rejected: %v", err)
	}
}
