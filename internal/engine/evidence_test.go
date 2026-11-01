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

func TestResponseMatchersNeverBecomeConfirmed(t *testing.T) {
	tmpl := testTemplate()
	tmpl.Matchers = []template.Matcher{{Type: "status", Value: "200"}, {Type: "word", Value: "marker"}}
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
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
