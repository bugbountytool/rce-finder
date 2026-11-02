package engine_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestResultTargetRedactsCredentialsAndQueryValues(t *testing.T) {
	u, _ := url.Parse("https://user:target-password@example.test/v1?access_token=target-secret")
	eng := engine.New(staticOOB{protocol: "http"}, engine.DefaultOptions())
	result := eng.RunTarget(context.Background(), scope.Target{Raw: u.String(), URL: u}, testTemplate())
	if strings.Contains(result.Target, "target-password") || strings.Contains(result.Target, "target-secret") || !strings.Contains(result.Target, "redacted") {
		t.Fatalf("result target retained sensitive data: %#v", result)
	}
}

// Cancelled/blocked jobs must also redact the target's query secrets; the
// scheduler's failedJob path used to leak them raw into results/snapshots.
func TestBlockedAndCancelledJobsRedactTarget(t *testing.T) {
	u, _ := url.Parse("https://example.test/v1?access_token=SUPERSECRET")
	tmpl := testTemplate()
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for r := range eng.RunJobs(ctx, engine.Jobs([]scope.Target{{Raw: u.String(), URL: u}}, []*template.Template{tmpl})) {
		if strings.Contains(r.Target, "SUPERSECRET") {
			t.Fatalf("blocked/cancelled result leaked query secret: %#v", r)
		}
	}
}

func TestEngineBlocksUnapprovedTargetBeforeIssueOrRequest(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8080/")
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	result := eng.RunTarget(context.Background(), scope.Target{Raw: u.String(), URL: u}, testTemplate())
	if result.Status != engine.StatusBlocked {
		t.Fatalf("unapproved target result = %#v", result)
	}
}

func TestEngineRejectsInvalidTemplateBeforeRequest(t *testing.T) {
	tmpl := testTemplate()
	tmpl.InjectionPoints = nil
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	result := eng.RunTarget(context.Background(), testTarget(), tmpl)
	if result.Status != engine.StatusError || !strings.Contains(result.Detail, "validation") {
		t.Fatalf("invalid template result = %#v", result)
	}
}

func TestRequestBodyLimitIsCappedAndEnforced(t *testing.T) {
	target, _ := url.Parse("https://example.test/")
	tmpl := &template.Template{Method: http.MethodPost, BodyContentType: "application/json", InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "input"}}}
	if _, err := engine.BuildRequest(context.Background(), target, tmpl, strings.Repeat("x", 1<<20), 1<<30); err == nil {
		t.Fatal("oversize body accepted despite oversized caller budget")
	}
}

func TestTemplatePathsCannotEscapeTarget(t *testing.T) {
	for _, path := range []string{"/outside", "../outside", "a/../../outside", "a\\..\\outside"} {
		target, _ := url.Parse("https://example.test/v1")
		tmpl := &template.Template{PathTemplate: path}
		if _, err := engine.BuildRequest(context.Background(), target, tmpl, "canary", 1024); err == nil {
			t.Errorf("unsafe template path accepted: %q", path)
		}
	}
}

func TestEngineRequiresLabPolicyForLocalTargets(t *testing.T) {
	if policy.Default().AllowPrivate {
		t.Fatal("default policy unexpectedly allows private targets")
	}
}
