package verify_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/model"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
	"github.com/bugbountytool/rce-finder/internal/verify"
)

type fixedOOB struct{ proto string }

func (f fixedOOB) Issue(context.Context, string) (string, error) { return "c.oob.test", nil }
func (f fixedOOB) Poll(_ context.Context, id string) (*oob.Interaction, error) {
	return &oob.Interaction{ProbeID: id, Protocol: f.proto}, nil
}
func (f fixedOOB) Close() error { return nil }

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The engine's CONFIRMED must be reproducible by the verification kernel from
// the equivalent observation. This ties the live scanner to the rule table.
func TestEngineConfirmedMatchesKernel(t *testing.T) {
	eng := engine.New(fixedOOB{proto: "dns"}, engine.DefaultOptions())
	eng.SetHTTPClient(&http.Client{Transport: rt(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	u, _ := scope.Parse("https://example.test/", eng.Options.Policy)
	tmpl := &template.Template{ID: "t", Name: "t", OOBProtocol: "dns", Method: "GET",
		PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	res := eng.RunTarget(context.Background(), scope.Target{Raw: u.String(), URL: u}, tmpl)
	if res.Status != engine.StatusConfirmed {
		t.Fatalf("engine status = %s", res.Status)
	}
	obs := verify.ObservationsFromStatus(model.StatusConfirmed, true, true)
	f, err := verify.New().Verify(model.Candidate{ID: "t", Class: "rce", Asset: res.Target}, obs)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusConfirmed {
		t.Fatalf("kernel disagreed with engine: %s", f.Status)
	}
}
