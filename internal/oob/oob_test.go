package oob

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPPollingClientFollowsDocumentedContract(t *testing.T) {
	var calls []*http.Request
	client := NewHTTPPollingClient("https://oob.test")
	client.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req)
		body := `{"canary":"token.oob.test"}`
		if req.URL.Path == "/poll" {
			body = `{"interaction":{"probe_id":"probe-1","protocol":"dns","source_ip":"127.0.0.1","at":"2026-01-01T00:00:00Z"}}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}

	canary, err := client.Issue(context.Background(), "probe-1")
	if err != nil || canary != "token.oob.test" {
		t.Fatalf("Issue() = %q, %v", canary, err)
	}
	interaction, err := client.Poll(context.Background(), "probe-1")
	if err != nil || interaction == nil || interaction.ProbeID != "probe-1" || interaction.Protocol != "dns" {
		t.Fatalf("Poll() = %#v, %v", interaction, err)
	}
	if len(calls) != 2 || calls[0].Method != http.MethodPost || calls[0].URL.Path != "/issue" || calls[1].Method != http.MethodGet || calls[1].URL.Query().Get("probe_id") != "probe-1" {
		t.Fatalf("requests = %#v", calls)
	}
}
