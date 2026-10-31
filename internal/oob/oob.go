// Package oob provides out-of-band interaction (canary) generation and
// callback correlation.
//
// This is the trust-critical component of the whole tool: it is what turns
// a payload injection into a *confirmed* result instead of a guess. The
// contract is simple:
//
//  1. Issue(probeID) returns a unique identifier (subdomain label or URL
//     path segment) that the caller embeds in a payload.
//  2. The target (if vulnerable) causes that identifier to be looked up via
//     DNS or requested via HTTP, against infrastructure the operator
//     controls.
//  3. Poll(probeID) reports whether a matching interaction was observed.
//
// This package ships with a Client interface and two implementations:
//
//   - LocalStubClient: a safe, no-network default used when no real OOB
//     backend is configured. It never reports a hit — it exists so the tool
//     builds and runs end-to-end (e.g. in CI, in --dry-run, or for template
//     development) without requiring infrastructure. It is NOT a
//     replacement for a real OOB backend during an actual engagement.
//   - HTTPPollingClient: talks to a self-hosted or third-party interaction
//     server over HTTP using a small, documented API (see docs/OOB.md).
//     Point this at infrastructure you operate and control; do not route
//     scan traffic through a shared or third-party instance you do not
//     trust with your findings.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Interaction is one observed OOB callback.
type Interaction struct {
	ProbeID  string    `json:"probe_id"`
	Protocol string    `json:"protocol"` // "dns" or "http"
	SourceIP string    `json:"source_ip,omitempty"`
	At       time.Time `json:"at"`
	RawInfo  string    `json:"raw_info,omitempty"`
}

// Client issues canary identifiers and reports observed interactions.
type Client interface {
	// Issue returns a unique canary token (e.g. a hostname label) for the
	// given probe ID. Embed the returned string into the payload wherever
	// the template calls for {{canary}}.
	Issue(ctx context.Context, probeID string) (canary string, err error)

	// Poll checks whether an interaction has been observed for probeID.
	// It returns (nil, nil) if nothing has arrived yet.
	Poll(ctx context.Context, probeID string) (*Interaction, error)

	// Close releases any resources (connections, listeners).
	Close() error
}

// NewLocalStubClient returns a Client that issues plausible-looking canary
// tokens but never observes a callback. Useful for template authoring,
// --dry-run, and CI smoke tests where no real OOB infrastructure exists.
func NewLocalStubClient(baseDomain string) Client {
	if baseDomain == "" {
		baseDomain = "oob.invalid.local"
	}
	return &localStubClient{baseDomain: baseDomain, issued: map[string]string{}}
}

type localStubClient struct {
	mu         sync.Mutex
	baseDomain string
	issued     map[string]string
}

func (c *localStubClient) Issue(_ context.Context, probeID string) (string, error) {
	token, err := randomHex(8)
	if err != nil {
		return "", err
	}
	canary := fmt.Sprintf("%s.%s", token, c.baseDomain)
	c.mu.Lock()
	c.issued[probeID] = canary
	c.mu.Unlock()
	return canary, nil
}

func (c *localStubClient) Poll(_ context.Context, _ string) (*Interaction, error) {
	// Deliberately always empty: this stub makes no network calls and
	// therefore can never observe a real interaction. Swap in
	// HTTPPollingClient (or your own Client implementation) for real scans.
	return nil, nil
}

func (c *localStubClient) Close() error { return nil }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HTTPPollingClient talks to a self-hosted interaction server. The server
// API is intentionally minimal — see docs/OOB.md for the reference
// implementation contract:
//
//	POST {BaseURL}/issue      {"probe_id": "..."}        -> {"canary": "..."}
//	GET  {BaseURL}/poll?probe_id=...                       -> {"interaction": {...} | null}
type HTTPPollingClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewHTTPPollingClient constructs a client against a self-hosted or
// otherwise trusted interaction server. Operators are responsible for
// ensuring that server is one they control — do not point this at shared
// third-party infrastructure for engagements where findings are sensitive.
func NewHTTPPollingClient(baseURL string) *HTTPPollingClient {
	return &HTTPPollingClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *HTTPPollingClient) Issue(ctx context.Context, probeID string) (string, error) {
	reqBody, _ := json.Marshal(map[string]string{"probe_id": probeID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/issue", jsonReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("issuing canary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("issue endpoint returned status %d", resp.StatusCode)
	}
	var out struct {
		Canary string `json:"canary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decoding issue response: %w", err)
	}
	return out.Canary, nil
}

func (c *HTTPPollingClient) Poll(ctx context.Context, probeID string) (*Interaction, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/poll?probe_id="+probeID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("polling canary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll endpoint returned status %d", resp.StatusCode)
	}
	var out struct {
		Interaction *Interaction `json:"interaction"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding poll response: %w", err)
	}
	return out.Interaction, nil
}

func (c *HTTPPollingClient) Close() error { return nil }
