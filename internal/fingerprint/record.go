package fingerprint

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bugbountytool/rce-finder/internal/evidence"
)

// Record is a bounded passive observation, never a vulnerability finding.
type Record struct {
	Target       string        `json:"target"`
	Confidence   int           `json:"confidence"`
	StatusCode   int           `json:"status_code"`
	ContentType  string        `json:"content_type,omitempty"`
	Server       string        `json:"server,omitempty"`
	PoweredBy    string        `json:"powered_by,omitempty"`
	TLSVersion   string        `json:"tls_version,omitempty"`
	TLSServer    string        `json:"tls_server_name,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	BodySHA256   string        `json:"body_sha256,omitempty"`
	Truncated    bool          `json:"body_truncated"`
}

// ReadResponse derives passive metadata from an already explicitly requested
// response. It follows no links, parses no scripts, and crawls no paths.
func ReadResponse(target string, resp *http.Response, maxBody int64, includeBody bool) (Record, error) {
	if maxBody <= 0 || maxBody > 1<<20 {
		maxBody = 1 << 20
	}
	record := Record{Target: target, StatusCode: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Server: resp.Header.Get("Server"), PoweredBy: resp.Header.Get("X-Powered-By"), Observations: FromHeaders(resp.Header)}
	if resp.TLS != nil {
		record.TLSVersion = tls.VersionName(resp.TLS.Version)
		record.TLSServer = resp.TLS.ServerName
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return record, fmt.Errorf("reading bounded fingerprint response: %w", err)
	}
	if int64(len(body)) > maxBody {
		body = body[:maxBody]
		record.Truncated = true
	}
	if includeBody {
		record.BodySHA256 = bodyDigest(body)
		if strings.Contains(strings.ToLower(record.ContentType), "html") {
			record.Observations = append(record.Observations, BodySignatures(body)...)
		}
	}
	record.Confidence = record.ConfidenceScore()
	return record, nil
}

func BodySignatures(body []byte) []Observation {
	if len(body) > 1<<20 {
		body = body[:1<<20]
	}
	lower := strings.ToLower(string(body))
	var out []Observation
	for product, markers := range map[string][]string{
		"django": {"csrfmiddlewaretoken"}, "rails": {"csrf-param"}, "laravel": {"laravel_session"},
	} {
		for _, marker := range markers {
			if strings.Contains(lower, marker) {
				out = append(out, Observation{Product: product, Source: "body-signature", Value: marker})
			}
		}
	}
	return out
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (r Record) Technologies() []string {
	seen := make(map[string]bool)
	var out []string
	for _, observation := range r.Observations {
		product := strings.ToLower(observation.Product)
		if product != "" && !seen[product] {
			seen[product] = true
			out = append(out, product)
		}
	}
	return out
}

func (r Record) ConfidenceScore() int {
	if len(r.Observations) == 0 {
		return 0
	}
	score := 30
	if r.BodySHA256 != "" {
		score += 20
	}
	if r.TLSVersion != "" {
		score += 10
	}
	if score > 80 {
		return 80
	}
	return score
}

func (r Record) Evidence(probeID string) evidence.Record {
	return evidence.New(evidence.KindFingerprint, probeID, time.Now().UTC(), map[string]string{"target": r.Target, "status_code": fmt.Sprint(r.StatusCode), "body_sha256": r.BodySHA256})
}

func (r Record) JSON() ([]byte, error) { return json.Marshal(r) }
