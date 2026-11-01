package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bugbountytool/rce-finder/internal/evidence"
	"github.com/bugbountytool/rce-finder/internal/findings"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/redact"
	"github.com/bugbountytool/rce-finder/internal/template"
)

// requestEvidence redacts URL user-info/query values and canary-bearing paths.
// It keeps request shape and body digest, not credentials or raw body contents.
func requestEvidence(req *http.Request, body []byte, probeID string, canary string) evidence.Record {
	u := *req.URL
	u.User = nil
	u.Path = redact.Text(u.Path, canary)
	u.RawQuery = redactQuery(u.Query())
	attrs := map[string]string{
		"method": req.Method, "url": u.String(), "body_sha256": bodyDigest(body),
		"content_type": safeContentType(req.Header.Get("Content-Type")),
	}
	return evidence.New(evidence.KindRequest, probeID, time.Now().UTC(), attrs)
}

func responseEvidence(resp *http.Response, body []byte, probeID string, truncated bool) evidence.Record {
	attrs := map[string]string{
		"status_code": fmt.Sprint(resp.StatusCode), "body_sha256": bodyDigest(body),
		"content_type":   safeContentType(resp.Header.Get("Content-Type")),
		"body_truncated": fmt.Sprint(truncated),
	}
	for _, name := range []string{"Content-Type", "Server", "X-Powered-By"} {
		if value := resp.Header.Get(name); value != "" {
			attrs[strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = value
		}
	}
	return evidence.New(evidence.KindResponse, probeID, time.Now().UTC(), attrs)
}

func interactionEvidence(interaction *oob.Interaction, probeID string) evidence.Record {
	attrs := map[string]string{"protocol": interaction.Protocol, "probe_id_matches": fmt.Sprint(interaction.ProbeID == probeID)}
	if interaction.SourceIP != "" {
		attrs["source_ip"] = interaction.SourceIP
	}
	return evidence.New(evidence.KindInteraction, probeID, interaction.At, attrs)
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func redactQuery(query url.Values) string {
	for _, values := range query {
		for i := range values {
			values[i] = "[redacted]"
		}
	}
	return query.Encode()
}

func safeContentType(value string) string {
	if mediaType, _, err := mime.ParseMediaType(value); err == nil {
		return mediaType
	}
	return ""
}

func readBoundedBody(body io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func finishResult(result Result) Result {
	result.FinishedAt = time.Now()
	result.Classification = result.Status
	result.Confidence = confidenceFor(result)
	result.Detail = redact.Text(result.Detail, result.Canary)
	result.Canary = ""
	return result
}

// Completed reports whether resume may reuse this result without another
// request. Inconclusive and error outcomes must be reviewed or retried.
func Completed(result Result) bool {
	switch result.Classification {
	case StatusConfirmed, StatusHighConfidence, StatusPotential, StatusNotVulnerable, StatusSkipped, StatusDryRun:
		return true
	default:
		return false
	}
}

func confidenceFor(result Result) Confidence {
	switch result.Status {
	case StatusConfirmed:
		return Confidence{Score: 100, Reasons: []string{"OOB interaction matched both probe ID and template protocol"}}
	case StatusHighConfidence:
		return Confidence{Score: 85, Reasons: []string{"multiple reproducible strong response indicators; not OOB confirmed"}}
	case StatusPotential:
		return Confidence{Score: 40, Reasons: []string{"weak or advisory applicability signal only"}}
	case StatusNotVulnerable:
		return Confidence{Score: 70, Reasons: []string{"completed negative test within configured callback timeout"}}
	case StatusInconclusive:
		return Confidence{Score: 10, Reasons: []string{"ambiguous, filtered, timed-out, or blocked response"}}
	default:
		return Confidence{Score: 0, Reasons: []string{string(result.Status)}}
	}
}

// classifyResponse handles declarative response hints without overclaiming.
// Ordinary OOB templates never turn a response hint into CONFIRMED.
func classifyResponse(t *template.Template, status int, body []byte) (Status, string) {
	if len(t.Matchers) == 0 {
		return "", ""
	}
	matched := 0
	for _, matcher := range t.Matchers {
		if matcher.Type == "word" && bytes.Contains(body, []byte(matcher.Value)) {
			matched++
		}
		if matcher.Type == "status" && fmt.Sprint(status) == matcher.Value {
			matched++
		}
	}
	if matched > 0 {
		return Status(findings.Potential), "one or more response indicators matched in a single response; reproducibility and manual review required"
	}
	return "", ""
}
