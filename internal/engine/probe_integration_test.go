package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/report"
	"github.com/bugbountytool/rce-finder/internal/requestctx"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/storage"
	"github.com/bugbountytool/rce-finder/internal/template"
)

type staticOOB struct{ protocol string }

func (s staticOOB) Issue(context.Context, string) (string, error) { return "canary.test", nil }
func (s staticOOB) Poll(_ context.Context, probeID string) (*oob.Interaction, error) {
	return &oob.Interaction{ProbeID: probeID, Protocol: s.protocol}, nil
}
func (s staticOOB) Close() error { return nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testTemplate() *template.Template {
	return &template.Template{ID: "t", Name: "t", Severity: template.SeverityHigh, OOBProtocol: "dns", Method: "GET", TimeoutSeconds: 1, PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
}

func testTarget() scope.Target {
	u, _ := url.Parse("https://example.test/")
	return scope.Target{Raw: u.String(), URL: u}
}

func TestRunOneRequiresMatchingOOBProtocol(t *testing.T) {
	eng := engine.New(staticOOB{protocol: "http"}, engine.Options{HTTPTimeout: time.Second, RequestsPerSec: 100})
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	result := eng.RunTarget(context.Background(), testTarget(), testTemplate())
	if result.Status != engine.StatusNotVulnerable || !strings.Contains(result.Detail, "no OOB callback") {
		t.Fatalf("mismatched protocol result = %#v", result)
	}
}

func TestRunOneConfirmsMatchingOOBCallback(t *testing.T) {
	eng := engine.New(staticOOB{protocol: "dns"}, engine.Options{HTTPTimeout: time.Second, RequestsPerSec: 100})
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	result := eng.RunTarget(context.Background(), testTarget(), testTemplate())
	if result.Status != engine.StatusConfirmed {
		t.Fatalf("matching callback result = %#v, want CONFIRMED", result)
	}
}

func TestRunOneSkipsAdvancedTemplateInSafeMode(t *testing.T) {
	tmpl := testTemplate()
	tmpl.Mode = "advanced-authorized"
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	result := eng.RunTarget(context.Background(), testTarget(), tmpl)
	if result.Status != engine.StatusSkipped {
		t.Fatalf("advanced template result = %#v, want SKIPPED", result)
	}
}

func TestRunOneBlocksRedirectRatherThanFollowingIt(t *testing.T) {
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	eng.SetHTTPClient(&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("Location", "https://outside-scope.test")
			return &http.Response{StatusCode: http.StatusFound, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	})
	result := eng.RunTarget(context.Background(), testTarget(), testTemplate())
	if result.Status != engine.StatusBlocked || !strings.Contains(result.Detail, "not followed") {
		t.Fatalf("redirect result = %#v", result)
	}
}

func TestRunOneCookieJarSendsSecretButResultAndFormatsDoNot(t *testing.T) {
	const secret = "cookie-secret-do-not-report"
	jar, err := requestctx.Cookies([]string{"session=" + secret})
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(staticOOB{protocol: "dns"}, engine.DefaultOptions())
	eng.Options.CookieJar = jar
	client := &http.Client{Jar: jar, Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "session="+secret {
			t.Errorf("Cookie header = %q", r.Header.Get("Cookie"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	eng.SetHTTPClient(client)
	result := eng.RunTarget(context.Background(), testTarget(), testTemplate())
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var sarif, markdown bytes.Buffer
	if err := report.WriteSARIF(&sarif, []engine.Result{result}); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteMarkdown(&markdown, []engine.Result{result}); err != nil {
		t.Fatal(err)
	}
	var table bytes.Buffer
	writer := report.NewTableWriter(&table)
	if err := writer.Write(result); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"JSON": string(data), "SARIF": sarif.String(), "Markdown": markdown.String(), "table": table.String(), "summary": writer.Summary()} {
		if strings.Contains(output, secret) || strings.Contains(output, "Cookie") {
			t.Errorf("%s contains cookie data: %s", name, output)
		}
	}
	snapshot := filepath.Join(t.TempDir(), "results.json")
	if err := storage.WriteSnapshot(snapshot, []engine.Result{result}); err != nil {
		t.Fatal(err)
	}
	snapshotData, _ := os.ReadFile(snapshot)
	if strings.Contains(string(snapshotData), secret) {
		t.Fatal("snapshot contains cookie secret")
	}
}
