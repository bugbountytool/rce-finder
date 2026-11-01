package requestctx

import (
	"net/url"
	"strings"
	"testing"
)

func TestCookiesDoNotEchoSecretOnValidationError(t *testing.T) {
	const secret = "session-secret-do-not-log"
	_, err := Cookies([]string{"session=" + secret + ";domain=example.test"})
	if err == nil {
		t.Fatal("invalid cookie accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("cookie validation error contains secret: %v", err)
	}
}

func TestCookiesAreScopedSecureAndPathIndependent(t *testing.T) {
	jar, err := Cookies([]string{"session=abc", "csrf=xyz"})
	if err != nil {
		t.Fatal(err)
	}
	secure, _ := url.Parse("https://example.test/anything")
	insecure, _ := url.Parse("http://example.test/")
	if got := jar.Cookies(secure); len(got) != 2 {
		t.Fatalf("HTTPS cookies = %#v", got)
	}
	if got := jar.Cookies(insecure); len(got) != 0 {
		t.Fatalf("secure cookies sent over HTTP: %#v", got)
	}
}
