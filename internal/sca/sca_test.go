package sca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/intel"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseGoMod(t *testing.T) {
	p := write(t, "go.mod", "module x\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgopkg.in/yaml.v3 v3.0.1 // indirect\n)\n")
	deps, err := ParseGoMod(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("deps = %d: %+v", len(deps), deps)
	}
	if deps[0].Name != "github.com/google/uuid" || deps[0].Version != "v1.6.0" || !deps[0].Direct {
		t.Fatalf("dep0 = %+v", deps[0])
	}
	if deps[1].Direct {
		t.Fatal("indirect dependency marked direct")
	}
}

func TestParsePackageLock(t *testing.T) {
	p := write(t, "package-lock.json", `{"packages":{"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}`)
	deps, err := ParsePackageLock(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, d := range deps {
		names[d.Name] = d.Version
	}
	if names["lodash"] != "4.17.20" || names["b"] != "2.0.0" {
		t.Fatalf("deps = %+v", names)
	}
}

func TestParseRequirements(t *testing.T) {
	p := write(t, "requirements.txt", "# comment\nrequests==2.31.0\nflask==2.0.1 ; python_version>\"3.8\"\n-e .\n")
	deps, err := ParseRequirements(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 || deps[0].Name != "requests" || deps[0].Version != "2.31.0" {
		t.Fatalf("deps = %+v", deps)
	}
}

// The intel tier model must never let a version-only match read as a confirmed
// vulnerability.
func TestAssessmentTiers(t *testing.T) {
	a := intel.Advisory{ID: "OSV-2024-1", Package: "lodash", Fixed: "4.17.21"}
	versionOnly := intel.Assess(a, false, intel.ThreatContext{})
	if versionOnly.Tier != intel.TierVersionOnly || versionOnly.Confidence > 0.4 {
		t.Fatalf("version-only tier = %d conf=%f", versionOnly.Tier, versionOnly.Confidence)
	}
	reachable := intel.Assess(a, true, intel.ThreatContext{})
	if reachable.Tier != intel.TierReachable || reachable.Confidence > 0.7 {
		t.Fatalf("reachable tier = %d conf=%f", reachable.Tier, reachable.Confidence)
	}
	kev := intel.Assess(a, true, intel.ThreatContext{InKEV: true})
	if kev.Tier != intel.TierThreatEnriched {
		t.Fatalf("kev tier = %d", kev.Tier)
	}
	// No assessment is ever a confirmation.
	for _, as := range []intel.Assessment{versionOnly, reachable, kev} {
		if !as.NeverConfirmed() {
			t.Fatal("assessment claimed confirmation")
		}
	}
}
