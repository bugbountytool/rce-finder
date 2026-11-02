package redact

import (
	"strings"
	"testing"
)

func TestURLRemovesCredentialsQueriesAndCanary(t *testing.T) {
	got := URL("https://user:secret@example.test/path/token.oob.test?q=token&empty=", "token.oob.test")
	for _, forbidden := range []string{"secret", "token.oob.test", "q=token"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("redacted URL contains %q: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "%5Bredacted-canary%5D") {
		t.Fatalf("canary not redacted: %s", got)
	}
}

func TestHeaderAllowlistRejectsSensitiveNames(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "X-API-Key", "X-Session-ID", "Proxy-Authorization"} {
		if HeaderName(name) {
			t.Errorf("sensitive header allowed: %s", name)
		}
	}
	if !HeaderName("Content-Type") {
		t.Fatal("safe content type rejected")
	}
}
