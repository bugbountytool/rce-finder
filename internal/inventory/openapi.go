// Package inventory imports explicit, operator-supplied application metadata.
// Imports do not create scan targets or send network traffic.
package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// LoadOpenAPIJSON reads OpenAPI v3 JSON. Server URLs and external references
// are intentionally ignored, so an inventory cannot expand scan scope.
func LoadOpenAPIJSON(path string) ([]Endpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading OpenAPI document: %w", err)
	}
	var doc struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing OpenAPI JSON: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("OpenAPI v3 JSON is required, got %q", doc.OpenAPI)
	}
	valid := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true}
	var out []Endpoint
	for pathName, operations := range doc.Paths {
		if !strings.HasPrefix(pathName, "/") {
			return nil, fmt.Errorf("invalid OpenAPI path %q", pathName)
		}
		for method := range operations {
			if valid[strings.ToLower(method)] {
				out = append(out, Endpoint{Method: strings.ToUpper(method), Path: pathName})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}
