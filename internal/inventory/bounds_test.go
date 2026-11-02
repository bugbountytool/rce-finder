package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportsRejectTrailingJSONAndDeepNesting(t *testing.T) {
	dir := t.TempDir()
	trailing := filepath.Join(dir, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"openapi":"3.0.0","paths":{}} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpenAPIJSON(trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON error = %v", err)
	}
	deep := strings.Repeat(`{"x":`, 70) + `null` + strings.Repeat("}", 70)
	path := filepath.Join(dir, "deep.json")
	if err := os.WriteFile(path, []byte(deep), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpenAPIJSON(path); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep JSON error = %v", err)
	}
}

func TestImportsRequireExplicitScope(t *testing.T) {
	path := writeImport(t, map[string]any{"log": map[string]any{"entries": []any{}}})
	if _, err := LoadHARJSON(path, nil); err == nil {
		t.Fatal("HAR accepted without explicit scope")
	}
}
