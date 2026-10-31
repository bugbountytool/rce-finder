// Package fingerprint derives conservative technology evidence from already
// captured HTTP exchanges. It performs no network I/O and never proves a
// vulnerability by itself.
package fingerprint

import (
	"net/http"
	"strings"
)

type Observation struct {
	Product string `json:"product"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source"`
	Value   string `json:"value"`
}

// FromHeaders returns low-confidence observations from standard response
// headers. Callers must preserve them as applicability hints only.
func FromHeaders(headers http.Header) []Observation {
	var out []Observation
	for _, header := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		for _, raw := range headers.Values(header) {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			product, version := splitProduct(value)
			out = append(out, Observation{Product: product, Version: version, Source: "header:" + strings.ToLower(header), Value: value})
		}
	}
	return out
}

func splitProduct(value string) (string, string) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", ""
	}
	parts := strings.SplitN(fields[0], "/", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]), parts[1]
	}
	return strings.ToLower(parts[0]), ""
}
