// Package requestctx validates static request context supplied by an operator.
package requestctx

import (
	"fmt"
	"net/http"
	"strings"
)

func Headers(entries []string) (http.Header, error) {
	h := make(http.Header)
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("header must use 'Name: value': %q", entry)
		}
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "User-Agent") {
			return nil, fmt.Errorf("header %q cannot be overridden", name)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header contains a newline")
		}
		h.Add(name, value)
	}
	return h, nil
}
