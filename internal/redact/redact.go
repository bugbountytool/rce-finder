// Package redact removes request secrets from text before it reaches logs,
// terminal output, result snapshots, or machine-readable reports.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

var sensitiveName = regexp.MustCompile(`(?i)(authorization|cookie|set-cookie|proxy-authorization|api[-_]?key|access[-_]?token|session)`)

// URL preserves endpoint metadata but removes user info and all query values.
func URL(raw string, secrets ...string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Text(raw, secrets...)
	}
	u.User = nil
	for _, secret := range secrets {
		if secret != "" {
			u.Path = Text(u.Path, secret)
		}
	}
	if u.RawQuery != "" {
		values := u.Query()
		for key := range values {
			values.Set(key, "[redacted]")
		}
		u.RawQuery = values.Encode()
	}
	return Text(u.String(), secrets...)
}

func Text(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted-canary]")
			value = strings.ReplaceAll(value, url.QueryEscape(secret), "[redacted-canary]")
			value = strings.ReplaceAll(value, url.PathEscape(secret), "[redacted-canary]")
		}
	}
	return value
}

// HeaderName allows only an explicit safe-header list, never Authorization or
// Cookie variants, to be retained as evidence metadata.
func HeaderName(name string) bool {
	if sensitiveName.MatchString(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "content-type", "server", "x-powered-by":
		return true
	default:
		return false
	}
}
