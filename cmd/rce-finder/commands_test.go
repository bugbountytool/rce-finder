package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureCLI(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cliStdout, cliStderr = &stdout, &stderr
	t.Cleanup(func() { cliStdout, cliStderr = os.Stdout, os.Stderr })
	return &stdout, &stderr
}

func TestFingerprintCommandRequestsOnlyExplicitURLs(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var starts []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		starts = append(starts, time.Now())
		mu.Unlock()
		w.Header().Set("Server", "test-server/1.0")
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte(server.URL+"/one?token=query-secret\n"+server.URL+"/two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, _ := captureCLI(t)
	if err := runFingerprint([]string{"-targets", targets, "-allow-private", "-i-am-authorized", "-rate", "20"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/one" || paths[1] != "/two" {
		t.Fatalf("requested paths = %#v", paths)
	}
	if starts[1].Sub(starts[0]) < 40*time.Millisecond {
		t.Fatalf("fingerprint requests started less than the configured interval apart: %s", starts[1].Sub(starts[0]))
	}
	if strings.Contains(stdout.String(), "query-secret") || !strings.Contains(stdout.String(), "redacted") {
		t.Fatalf("fingerprint output did not redact query secrets: %s", stdout.String())
	}
}

func TestFingerprintCommandCancelsPendingRequest(t *testing.T) {
	requested := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested <- struct{}{}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte(server.URL+"/one\n"+server.URL+"/two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	captureCLI(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- fingerprintWithContext(ctx, []string{"-targets", targets, "-allow-private", "-i-am-authorized", "-rate", "1"})
	}()
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("first fingerprint request was not sent")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fingerprint did not stop after cancellation")
	}
	if len(requested) != 0 {
		t.Fatal("fingerprint sent another request after cancellation")
	}
}

func TestTemplateCommandsValidateLocalDirectory(t *testing.T) {
	captureCLI(t)
	if err := runTemplates([]string{"validate", "-templates", "../../templates"}); err != nil {
		t.Fatalf("templates validate: %v", err)
	}
	if err := runTemplates([]string{"inspect", "-templates", "../../templates", "-id", "jndi-generic-oob"}); err != nil {
		t.Fatalf("templates inspect: %v", err)
	}
}

func TestInventoryDoesNotPrintSecretsOrContactTargets(t *testing.T) {
	var contacted bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	defer server.Close()
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte(server.URL+"/v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const secret = "har-cookie-authorization-secret"
	har := filepath.Join(dir, "import.har")
	data := `{"log":{"entries":[{"request":{"method":"GET","url":"` + server.URL + `/v1/items?token=` + secret + `","headers":[{"name":"Cookie","value":"` + secret + `"}]}},{"request":{"method":"GET","url":"https://outside.example/v1/items"}}]}}`
	if err := os.WriteFile(har, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := captureCLI(t)
	if err := runInventory([]string{"-targets", targets, "-allow-private", "-har", har}); err != nil {
		t.Fatal(err)
	}
	if contacted {
		t.Fatal("inventory contacted a target")
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) || strings.Contains(stdout.String(), "outside.example") {
		t.Fatalf("inventory leaked secret or expanded scope: %s %s", stdout.String(), stderr.String())
	}
}

func TestDryRunDoesNotPrintCanary(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte("https://example.test/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, _ := captureCLI(t)
	if err := runScan([]string{"-targets", targets, "-i-am-authorized", "-dry-run", "-allow-unsigned-local-templates", "-templates", "../../templates"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), ".oob.invalid.local") || strings.Contains(stdout.String(), "q=") && !strings.Contains(stdout.String(), "redacted") {
		t.Fatalf("dry-run leaked canary: %s", stdout.String())
	}
}
