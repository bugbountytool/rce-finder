package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/policy"
)

func writeTargets(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAcceptsExplicitHTTPAndHTTPSURLs(t *testing.T) {
	p := policy.Default()
	p.AllowPrivate = true
	targets, err := LoadWithPolicy(writeTargets(t, "# authorized targets\n\nhttps://example.test/api\n http://127.0.0.1:8080/x \n"), p)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(targets) != 2 || targets[0].Raw != "https://example.test/api" || targets[1].URL.Host != "127.0.0.1:8080" {
		t.Fatalf("Load() = %#v", targets)
	}
}

func TestLoadDefaultPolicyRejectsPrivateTargets(t *testing.T) {
	if _, err := Load(writeTargets(t, "http://127.0.0.1:8080\n")); err == nil {
		t.Fatal("Load accepted loopback target without explicit policy opt-in")
	}
}

func TestLoadRejectsInvalidOrOutOfScopeTargetFiles(t *testing.T) {
	for _, content := range []string{"", "# comment only\n", "example.test\n", "ftp://example.test\n"} {
		_, err := Load(writeTargets(t, content))
		if err == nil {
			t.Fatalf("Load(%q) succeeded, want error", content)
		}
	}
	_, err := Load(writeTargets(t, "https://ok.test\nnot-a-url\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("mixed target Load() error = %v, want line-specific error", err)
	}
}
