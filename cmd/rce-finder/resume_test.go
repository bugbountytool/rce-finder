package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/storage"
	"github.com/bugbountytool/rce-finder/internal/template"
)

type neverOOB struct{}

func (neverOOB) Issue(context.Context, string) (string, error)          { return "local-canary.oob.test", nil }
func (neverOOB) Poll(context.Context, string) (*oob.Interaction, error) { return nil, nil }
func (neverOOB) Close() error                                           { return nil }

func TestResumeDoesNotResendCompletedJob(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	target := scope.Target{Raw: u.String(), URL: u}
	tmpl := &template.Template{ID: "resume", Name: "resume", OOBProtocol: "http", Method: "GET", TimeoutSeconds: 1, PayloadTemplate: "{{canary}}", InjectionPoints: []template.InjectionPoint{{Location: "query", Name: "q"}}}
	if err := tmpl.Validate(); err != nil {
		t.Fatal(err)
	}
	opts := engine.DefaultOptions()
	opts.RequestsPerSec = 1000
	opts.PerHostRPS = 1000
	opts.MaxRetries = 0
	opts.Policy = policy.Policy{Mode: policy.ModeSafeValidation, AllowPrivate: true}
	eng := engine.New(neverOOB{}, opts)
	client := *server.Client()
	client.Timeout = time.Second
	eng.SetHTTPClient(&client)
	result := eng.RunTarget(context.Background(), target, tmpl)
	job := engine.NewJob(target, tmpl)
	result.JobID = job.ID
	if result.Status != engine.StatusNotVulnerable {
		t.Fatalf("first result = %#v", result)
	}
	snapshotPath := filepath.Join(t.TempDir(), "scan.json")
	snapshot := storage.Snapshot{ScanID: "scan", ScopeFingerprint: engine.ScopeFingerprint([]scope.Target{target}), TemplateFingerprint: engine.TemplateFingerprint([]*template.Template{tmpl}), CompletedJobIDs: []string{job.ID}, Results: []engine.Result{result}}
	if err := storage.WriteJobSnapshot(snapshotPath, snapshot); err != nil {
		t.Fatal(err)
	}
	stored, err := storage.ReadSnapshot(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	jobs := engine.Jobs([]scope.Target{target}, []*template.Template{tmpl})
	if stored.ScopeFingerprint != engine.ScopeFingerprint([]scope.Target{target}) || stored.TemplateFingerprint != engine.TemplateFingerprint([]*template.Template{tmpl}) {
		t.Fatal("matching fingerprints rejected")
	}
	completed := map[string]bool{}
	for _, id := range stored.CompletedJobIDs {
		completed[id] = true
	}
	var pending []engine.Job
	for _, job := range jobs {
		if !completed[job.ID] {
			pending = append(pending, job)
		}
	}
	for range eng.RunJobs(context.Background(), pending) {
	}
	if requests != 1 {
		t.Fatalf("resume sent completed request again: %d requests", requests)
	}
	other := tmpl
	copyTemplate := *tmpl
	other = &copyTemplate
	other.Name = "changed"
	if engine.TemplateFingerprint([]*template.Template{other}) == stored.TemplateFingerprint {
		t.Fatal("template fingerprint did not change")
	}
}

func TestSnapshotContainsNoCookieOrAuthorizationFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := storage.WriteJobSnapshot(path, storage.Snapshot{Results: []engine.Result{}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"cookie", "authorization", "headers"} {
		if _, ok := generic[forbidden]; ok {
			t.Errorf("snapshot contains %s", forbidden)
		}
	}
}
