package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/scope"
)

func testTargets(t *testing.T) []scope.Target {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("https://api.example.test/v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	targets, err := scope.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return targets
}

func writeImport(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "import.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHARImportsOnlyFinalURLsInsideExplicitScope(t *testing.T) {
	entries := []any{
		map[string]any{"request": map[string]any{"method": "POST", "url": "https://api.example.test/v1/users?token=secret", "headers": []map[string]string{{"name": "Cookie", "value": "secret"}}}},
		map[string]any{"request": map[string]any{"method": "GET", "url": "https://api.example.test/v2/outside"}},
		map[string]any{"request": map[string]any{"method": "GET", "url": "https://evil.example.test/v1/users"}},
		map[string]any{"request": map[string]any{"method": "GET", "url": "http://api.example.test/v1/users"}},
		map[string]any{"request": map[string]any{"method": "GET", "url": "https://api.example.test:444/v1/users"}},
	}
	path := writeImport(t, map[string]any{"log": map[string]any{"entries": entries}})
	got, err := LoadHARJSON(path, testTargets(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{Method: "POST", Path: "/v1/users", Source: "har"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadHARJSON() = %#v, want %#v", got, want)
	}
}

func TestPostmanIgnoresVariablesAndOutOfScopeURLs(t *testing.T) {
	path := writeImport(t, map[string]any{
		"info": map[string]any{"name": "test"},
		"item": []any{map[string]any{"item": []any{
			map[string]any{"request": map[string]any{"method": "POST", "url": map[string]any{"raw": "https://api.example.test/v1/users?secret=value"}}},
			map[string]any{"request": map[string]any{"method": "GET", "url": "https://outside.example.test/v1/users"}},
			map[string]any{"request": map[string]any{"method": "GET", "url": "{{baseUrl}}/v1/users"}},
		}}},
	})
	got, err := LoadPostmanJSON(path, testTargets(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{Method: "POST", Path: "/v1/users", Source: "postman"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadPostmanJSON() = %#v, want %#v", got, want)
	}
}

func TestOpenAPIIgnoresServersCallbacksWebhooksAndExternalRefs(t *testing.T) {
	operation := map[string]any{
		"callbacks": map[string]any{"callback": map[string]any{
			"{$request.body#/url}": map[string]any{"post": map[string]any{}},
		}},
		"requestBody": map[string]any{"$ref": "https://outside.example.test/schema"},
	}
	path := writeImport(t, map[string]any{
		"openapi":  "3.1.0",
		"servers":  []any{map[string]any{"url": "https://outside.example.test"}},
		"paths":    map[string]any{"/users": map[string]any{"post": operation}},
		"webhooks": map[string]any{"outside": map[string]any{"post": map[string]any{}}},
	})
	got, err := LoadOpenAPIJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{Method: "POST", Path: "/users"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadOpenAPIJSON() = %#v, want %#v", got, want)
	}
}
