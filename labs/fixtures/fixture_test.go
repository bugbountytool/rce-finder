package labfixture

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVulnerableFixtureExtractsExactCanaryWithoutExecutingPayload(t *testing.T) {
	var callback string
	fixture := &Server{Vulnerable: true, Callback: func(canary string) { callback = canary }}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"template":"fetch('http://abc123.oob.test/callback')"}`))
	resp := httptest.NewRecorder()
	fixture.ServeHTTP(resp, req)
	if callback != "abc123.oob.test" {
		t.Fatalf("callback canary = %q", callback)
	}
}

func TestPatchedFixtureNeverCallsBack(t *testing.T) {
	called := false
	fixture := &Server{Callback: func(string) { called = true }}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"template":"abc123.oob.test"}`))
	fixture.ServeHTTP(httptest.NewRecorder(), req)
	if called {
		t.Fatal("patched fixture generated callback")
	}
}
