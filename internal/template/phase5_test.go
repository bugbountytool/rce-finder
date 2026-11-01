package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsafeCapabilityTemplatesFailBeforeExecution(t *testing.T) {
	for _, mode := range []string{"advanced-authorized", "passive"} {
		tmpl := validTemplate()
		tmpl.Mode = mode
		if err := tmpl.Validate(); err == nil {
			t.Errorf("mode %q accepted for active probing", mode)
		}
	}
}

func TestPrerequisiteRequestConstraintsAreEnforced(t *testing.T) {
	tmpl := validTemplate()
	tmpl.Prerequisites.AllowedMethods = []string{"POST"}
	if err := tmpl.Validate(); err == nil {
		t.Fatal("method outside declared prerequisites accepted")
	}
	tmpl = validTemplate()
	tmpl.Prerequisites.AllowedContentTypes = []string{"application/json"}
	if err := tmpl.Validate(); err == nil {
		t.Fatal("content type outside declared prerequisites accepted")
	}
}

func TestLoadDirRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	data := "id: test\nname: Test\noob_protocol: dns\npayload: '{{canary}}'\nunknown_field: true\ninjection_points:\n  - location: query\n    name: q\n"
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestSafePacksValidate(t *testing.T) {
	if _, err := LoadDir("../../templates/packs"); err != nil {
		t.Fatalf("safe packs do not validate: %v", err)
	}
}
