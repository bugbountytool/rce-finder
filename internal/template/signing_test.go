package template

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func signedPack(t *testing.T) (string, string, Manifest) {
	t.Helper()
	dir := t.TempDir()
	data := []byte("id: test\nname: Test\noob_protocol: dns\npayload: '{{canary}}'\ninjection_points:\n  - location: query\n    name: q\n")
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	proofs, err := FileProofs(dir)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := SignManifest(Manifest{Version: "rce-finder/signed-pack-v1", PackID: "test-pack", KeyID: "local-test", ExpiresAt: time.Now().Add(time.Hour), Files: proofs}, private)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal([]TrustedKey{{KeyID: "local-test", PublicKey: base64.StdEncoding.EncodeToString(public), ExpiresAt: time.Now().Add(time.Hour)}})
	return dir, string(keys), manifest
}

func TestSignedPackVerification(t *testing.T) {
	dir, keys, manifest := signedPack(t)
	var trusted []TrustedKey
	if err := json.Unmarshal([]byte(keys), &trusted); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(dir, manifest, trusted, time.Now()); err != nil {
		t.Fatalf("valid signed pack rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte("altered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(dir, manifest, trusted, time.Now()); err == nil {
		t.Fatal("altered signed file accepted")
	}
}

func TestSigningRejectsUnknownExpiredAndUnsigned(t *testing.T) {
	dir, keys, manifest := signedPack(t)
	var trusted []TrustedKey
	_ = json.Unmarshal([]byte(keys), &trusted)
	if err := VerifyManifest(dir, manifest, []TrustedKey{}, time.Now()); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := VerifyManifest(dir, manifest, trusted, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired key or pack accepted")
	}
	if err := VerifyDir(dir, "", false); err == nil {
		t.Fatal("unsigned local templates accepted without opt-in")
	}
	if err := VerifyDir(dir, "", true); err != nil {
		t.Fatalf("explicit unsigned local templates rejected: %v", err)
	}
}
