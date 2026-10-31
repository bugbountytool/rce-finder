// Package evidence stores tamper-evident, redacted records used to support a
// finding. It deliberately stores metadata and hashes rather than raw secrets.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

type Kind string

const (
	KindRequest     Kind = "request"
	KindResponse    Kind = "response"
	KindInteraction Kind = "oob-interaction"
	KindFingerprint Kind = "fingerprint"
)

// Record contains safe metadata that can be retained with a scan finding.
// Sensitive values must be redacted by the caller before construction.
type Record struct {
	Kind       Kind              `json:"kind"`
	ProbeID    string            `json:"probe_id,omitempty"`
	Observed   time.Time         `json:"observed_at"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Digest     string            `json:"sha256"`
}

// New returns a deterministic digest over the public evidence fields.
func New(kind Kind, probeID string, observed time.Time, attributes map[string]string) Record {
	copyAttrs := make(map[string]string, len(attributes))
	keys := make([]string, 0, len(attributes))
	for k, v := range attributes {
		copyAttrs[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{string(kind), probeID, observed.UTC().Format(time.RFC3339Nano)}
	for _, k := range keys {
		parts = append(parts, k+"="+copyAttrs[k])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return Record{Kind: kind, ProbeID: probeID, Observed: observed.UTC(), Attributes: copyAttrs, Digest: hex.EncodeToString(sum[:])}
}
