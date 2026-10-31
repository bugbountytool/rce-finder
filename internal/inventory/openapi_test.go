package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOpenAPIJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.json")
	if err := os.WriteFile(path, []byte(`{"openapi":"3.0.3","paths":{"/users":{"get":{},"post":{}},"/ignored":{"trace":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOpenAPIJSON(path)
	if err != nil || len(got) != 2 || got[0].Method != "GET" {
		t.Fatalf("LoadOpenAPIJSON() = %#v, %v", got, err)
	}
}
