package template

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ManifestName = "pack.signatures.json"

type Manifest struct {
	Version   string      `json:"version"`
	PackID    string      `json:"pack_id"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	KeyID     string      `json:"key_id"`
	Files     []FileProof `json:"files"`
	Signature string      `json:"signature"`
}

type FileProof struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type TrustedKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	ExpiresAt time.Time `json:"expires_at"`
}

func SignableManifest(m Manifest) ([]byte, error) {
	m.Signature = ""
	return json.Marshal(m)
}

func FileProofs(dir string) ([]FileProof, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var proofs []FileProof
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		proofs = append(proofs, FileProof{Path: entry.Name(), SHA256: hex.EncodeToString(digest[:])})
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].Path < proofs[j].Path })
	if len(proofs) == 0 {
		return nil, fmt.Errorf("signed template pack has no YAML files")
	}
	return proofs, nil
}

func SignManifest(m Manifest, privateKey ed25519.PrivateKey) (Manifest, error) {
	data, err := SignableManifest(m)
	if err != nil {
		return Manifest{}, err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, data))
	return m, nil
}

// VerifyManifest authenticates exact local file bytes and key/manifest expiry.
// No template bytes are fetched or executed during verification.
func VerifyManifest(dir string, m Manifest, keys []TrustedKey, now time.Time) error {
	if m.Version != "rce-finder/signed-pack-v1" || m.PackID == "" || m.KeyID == "" {
		return fmt.Errorf("invalid signed template pack metadata")
	}
	if !m.ExpiresAt.IsZero() && !now.Before(m.ExpiresAt) {
		return fmt.Errorf("signed template pack expired at %s", m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	var key *TrustedKey
	for i := range keys {
		if keys[i].KeyID == m.KeyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return fmt.Errorf("template pack signing key %q is not trusted", m.KeyID)
	}
	if !key.ExpiresAt.IsZero() && !now.Before(key.ExpiresAt) {
		return fmt.Errorf("trusted template signing key %q has expired", key.KeyID)
	}
	public, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted template signing key %q is invalid", key.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("template pack signature is malformed")
	}
	message, err := SignableManifest(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return fmt.Errorf("template pack signature verification failed")
	}
	actual, err := FileProofs(dir)
	if err != nil {
		return err
	}
	if len(actual) != len(m.Files) {
		return fmt.Errorf("template pack file set differs from signed manifest")
	}
	for i := range actual {
		if actual[i] != m.Files[i] {
			return fmt.Errorf("template file %q differs from signed manifest", actual[i].Path)
		}
	}
	return nil
}

func ReadTrustedKeys(path string) ([]TrustedKey, error) {
	if path == "" {
		return nil, fmt.Errorf("trusted public key file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []TrustedKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("parsing trusted template keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("trusted template key file is empty")
	}
	return keys, nil
}

func VerifyDir(dir, keyPath string, allowUnsigned bool) error {
	manifestPath := filepath.Join(dir, ManifestName)
	data, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		if allowUnsigned {
			_, err := LoadDir(dir)
			return err
		}
		return fmt.Errorf("template pack is unsigned; explicit --allow-unsigned-local-templates is required for local templates")
	}
	if err != nil {
		return err
	}
	keys, err := ReadTrustedKeys(keyPath)
	if err != nil {
		return err
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("parsing signed template manifest: %w", err)
	}
	if err := VerifyManifest(dir, manifest, keys, time.Now().UTC()); err != nil {
		return err
	}
	_, err = LoadDir(dir)
	return err
}
