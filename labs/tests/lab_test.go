//go:build integration

package labtest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
	labfixture "github.com/bugbountytool/rce-finder/labs/fixtures"
	laboob "github.com/bugbountytool/rce-finder/labs/oob"
)

func testHTTPPack() *template.Template {
	return &template.Template{ID: "lab-http-safe", Name: "local safe fixture", OOBProtocol: "http", Method: "POST", BodyContentType: "application/json", TimeoutSeconds: 1, PayloadTemplate: "fetch('http://{{canary}}/callback')", InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "template"}}}
}

func labEngine(t *testing.T, oobServer *laboob.Server, fixture *labfixture.Server) (*engine.Engine, scope.Target) {
	t.Helper()
	targetServer := httptest.NewServer(fixture)
	t.Cleanup(targetServer.Close)
	u, _ := url.Parse(targetServer.URL)
	target := scope.Target{Raw: u.String(), URL: u}
	opts := engine.DefaultOptions()
	opts.RequestsPerSec = 1000
	opts.PerHostRPS = 1000
	opts.MaxRetries = 0
	opts.HTTPTimeout = time.Second
	opts.Policy = policy.Policy{Mode: policy.ModeSafeValidation, AllowPrivate: true}
	eng := engine.New(oobServer.Client(), opts)
	client := *http.DefaultClient
	client.Timeout = time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	eng.SetHTTPClient(&client)
	return eng, target
}

func TestPositivePatchedAndCorrelationCases(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vulnerable bool
		mode       string
		want       engine.Status
	}{{"positive callback", true, "", engine.StatusConfirmed}, {"patched negative", false, "", engine.StatusNotVulnerable}, {"wrong probe ID", true, "probe_id", engine.StatusNotVulnerable}, {"wrong protocol", true, "protocol", engine.StatusNotVulnerable}} {
		t.Run(tc.name, func(t *testing.T) {
			oobServer := laboob.New()
			defer oobServer.Close()
			oobServer.SetMode(tc.mode, 0)
			fixture := &labfixture.Server{Vulnerable: tc.vulnerable, Callback: oobServer.ObserveCanary}
			eng, target := labEngine(t, oobServer, fixture)
			result := eng.RunTarget(context.Background(), target, testHTTPPack())
			if result.Status != tc.want {
				t.Fatalf("status = %s, want %s (%s)", result.Status, tc.want, result.Detail)
			}
		})
	}
}

func TestDelayedCallback(t *testing.T) {
	oobServer := laboob.New()
	defer oobServer.Close()
	oobServer.SetMode("", 100*time.Millisecond)
	fixture := &labfixture.Server{Vulnerable: true, Callback: func(canary string) { go oobServer.ObserveCanary(canary) }}
	eng, target := labEngine(t, oobServer, fixture)
	if result := eng.RunTarget(context.Background(), target, testHTTPPack()); result.Status != engine.StatusConfirmed {
		t.Fatalf("delayed callback = %#v", result)
	}
}

func TestRedirectWAFAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want engine.Status
	}{{"redirect", engine.StatusBlocked}, {"waf", engine.StatusInconclusive}, {"malformed", engine.StatusNotVulnerable}} {
		t.Run(tc.mode, func(t *testing.T) {
			oobServer := laboob.New()
			defer oobServer.Close()
			eng, target := labEngine(t, oobServer, &labfixture.Server{Mode: tc.mode})
			if got := eng.RunTarget(context.Background(), target, testHTTPPack()).Status; got != tc.want {
				t.Fatalf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCancellationAndConcurrency(t *testing.T) {
	oobServer := laboob.New()
	defer oobServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	eng, target := labEngine(t, oobServer, &labfixture.Server{Vulnerable: true})
	if got := eng.RunTarget(ctx, target, testHTTPPack()).Status; got == engine.StatusConfirmed {
		t.Fatal("cancelled request was confirmed")
	}
	var calls atomic.Int32
	fixture := &labfixture.Server{Vulnerable: false}
	eng, target = labEngine(t, oobServer, fixture)
	eng.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	templates := []*template.Template{testHTTPPack(), testHTTPPack(), testHTTPPack()}
	for i := range templates {
		templates[i].ID = string(rune('a' + i))
	}
	for range eng.Run(context.Background(), []scope.Target{target}, templates) {
	}
	if calls.Load() != 3 {
		t.Fatalf("concurrent calls = %d", calls.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var _ = json.Valid
var _ = oob.Interaction{}
