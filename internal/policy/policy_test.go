package policy

import (
	"net/url"
	"testing"
)

func TestDefaultPolicyRejectsPrivateAndCredentialURLs(t *testing.T) {
	p := Default()
	for _, raw := range []string{"http://127.0.0.1", "http://user:secret@example.test"} {
		u, _ := url.Parse(raw)
		if err := p.ValidateTarget(u); err == nil {
			t.Fatalf("ValidateTarget(%q) succeeded", raw)
		}
	}
	local, _ := url.Parse("http://127.0.0.1")
	p.AllowPrivate = true
	if err := p.ValidateTarget(local); err != nil {
		t.Fatalf("explicit lab target rejected: %v", err)
	}
}

func TestPolicyModes(t *testing.T) {
	p := Default()
	if !p.AllowsTemplate(ModeSafeValidation) || p.AllowsTemplate(ModeAdvanced) {
		t.Fatal("safe policy mode permissions are wrong")
	}
}
