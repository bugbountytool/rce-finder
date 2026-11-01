package laboob

import (
	"context"
	"net/http"
	"testing"
)

func TestHTTPCallbackPathCorrelatesIssuedCanary(t *testing.T) {
	server := New()
	defer server.Close()
	client := server.Client()
	canary, err := client.Issue(context.Background(), "http-probe")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(server.CanaryURL(canary))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	interaction, err := client.Poll(context.Background(), "http-probe")
	if err != nil || interaction == nil {
		t.Fatalf("HTTP callback not correlated: %#v, %v", interaction, err)
	}
}
