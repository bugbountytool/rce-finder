package laboob

import (
	"context"
	"testing"
)

func TestIssueObservePollCorrelation(t *testing.T) {
	server := New()
	defer server.Close()
	client := server.Client()
	canary, err := client.Issue(context.Background(), "probe-1")
	if err != nil {
		t.Fatal(err)
	}
	server.ObserveCanary(canary)
	interaction, err := client.Poll(context.Background(), "probe-1")
	if err != nil {
		t.Fatal(err)
	}
	if interaction == nil || interaction.ProbeID != "probe-1" || interaction.Protocol != "http" {
		t.Fatalf("interaction = %#v", interaction)
	}
}
