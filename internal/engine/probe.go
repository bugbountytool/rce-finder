// Package engine orchestrates the scan: for every (target, template) pair
// it issues a canary, builds and sends a single non-destructive HTTP
// request carrying the payload, then hands off to the correlator to wait
// for an OOB callback.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bugbountytool/rce-finder/internal/evidence"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/redact"
	"github.com/bugbountytool/rce-finder/internal/requestbody"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

// Status is the final, deliberately binary (plus error) outcome of a probe.
type Status string

const (
	StatusConfirmed      Status = "CONFIRMED"
	StatusNotVulnerable  Status = "NOT_VULNERABLE"
	StatusHighConfidence Status = "HIGH_CONFIDENCE"
	StatusPotential      Status = "POTENTIAL"
	StatusInconclusive   Status = "INCONCLUSIVE"
	StatusDryRun         Status = "DRY_RUN"
	StatusSkipped        Status = "SKIPPED"
	StatusBlocked        Status = "BLOCKED"
	StatusError          Status = "ERROR"
)

// Result is the outcome of running one template against one target.
type Result struct {
	ProbeID    string   `json:"probe_id"`
	ScanID     string   `json:"scan_id,omitempty"`
	JobID      string   `json:"job_id,omitempty"`
	Target     string   `json:"target"`
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	References []string `json:"references,omitempty"`
	Status     Status   `json:"status"`
	// Classification is the same value as Status, explicitly named for report
	// consumers. CONFIRMED requires an exact correlated OOB interaction.
	Classification   Status            `json:"classification"`
	Confidence       Confidence        `json:"confidence"`
	Evidence         []evidence.Record `json:"evidence,omitempty"`
	Remediation      string            `json:"remediation,omitempty"`
	CWEs             []string          `json:"cwe,omitempty"`
	CVEs             []string          `json:"cve,omitempty"`
	Technologies     []string          `json:"technologies,omitempty"`
	Canary           string            `json:"-"`
	TransientNetwork bool              `json:"-"`
	CanaryDigest     string            `json:"canary_sha256,omitempty"`
	Detail           string            `json:"detail,omitempty"`
	SkipReason       string            `json:"skip_reason,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
}

type Confidence struct {
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}

// Options configures a scan run.
type Options struct {
	Concurrency      int
	RequestsPerSec   float64
	DryRun           bool
	HTTPTimeout      time.Duration
	MaxResponseBytes int64
	Policy           policy.Policy
	Headers          http.Header
	CookieJar        http.CookieJar
	MaxBodyBytes     int64
	PerHostRPS       float64
	MaxRetries       int
	RetryBackoff     time.Duration
	HostErrorBudget  int
	ScanID           string
	Progress         func(ProgressEvent)
}

func DefaultOptions() Options {
	return Options{
		Concurrency:      5,
		RequestsPerSec:   2,
		DryRun:           false,
		HTTPTimeout:      10 * time.Second,
		MaxResponseBytes: 1 << 20, // 1 MiB
		MaxBodyBytes:     requestbody.MaxBytes,
		PerHostRPS:       1,
		MaxRetries:       2,
		RetryBackoff:     250 * time.Millisecond,
		HostErrorBudget:  5,
		Policy:           policy.Default(),
	}
}

// Engine runs templates against targets.
type Engine struct {
	OOB     oob.Client
	Options Options
	limiter *rateLimiter
	client  *http.Client
	hosts   map[string]*hostState
	hostsMu sync.Mutex
}

func New(oobClient oob.Client, opts Options) *Engine {
	if opts.Policy.Mode == "" {
		opts.Policy = policy.Default()
	}
	return &Engine{
		OOB:     oobClient,
		Options: opts,
		limiter: newRateLimiter(opts.RequestsPerSec),
		hosts:   make(map[string]*hostState),
		client: &http.Client{
			Timeout: opts.HTTPTimeout,
			Jar:     opts.CookieJar,
			// Redirects may leave the operator's explicit scope. Record the
			// response but never follow it automatically.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// job is one (target, template) unit of work.
type job = Job

// Run executes every template against every target and streams results to
// the returned channel, closing it when the scan is complete.
func (e *Engine) Run(ctx context.Context, targets []scope.Target, templates []*template.Template) <-chan Result {
	return e.RunJobs(ctx, Jobs(targets, templates))
}

func (e *Engine) runOne(ctx context.Context, j job) Result {
	started := time.Now()
	probeID := uuid.NewString()

	base := Result{
		ProbeID:      probeID,
		ScanID:       e.Options.ScanID,
		JobID:        j.ID,
		Target:       redact.URL(j.Target.Raw),
		TemplateID:   j.Tmpl.ID,
		Name:         j.Tmpl.Name,
		Severity:     string(j.Tmpl.Severity),
		References:   j.Tmpl.References,
		Remediation:  j.Tmpl.Remediation,
		CWEs:         j.Tmpl.CWEs,
		CVEs:         j.Tmpl.CVEs,
		Technologies: j.Tmpl.Technologies,
		StartedAt:    started,
	}
	if !e.Options.Policy.AllowsTemplate(policy.Mode(j.Tmpl.EffectiveMode())) {
		base.Status = StatusSkipped
		base.Detail = fmt.Sprintf("template requires %s mode; scan policy is %s", j.Tmpl.EffectiveMode(), e.Options.Policy.Mode)
		base.SkipReason = base.Detail
		return finishResult(base)
	}
	if err := j.Tmpl.Validate(); err != nil {
		base.Status = StatusError
		base.Detail = "template validation failed before request construction"
		return finishResult(base)
	}
	if j.Target.URL == nil || e.Options.Policy.ValidateTarget(j.Target.URL) != nil {
		base.Status = StatusBlocked
		base.Detail = "target denied by explicit scope and network policy"
		base.SkipReason = base.Detail
		return finishResult(base)
	}

	canary, err := e.OOB.Issue(ctx, probeID)
	if err != nil {
		base.Status = StatusError
		base.Detail = fmt.Sprintf("issuing canary: %v", err)
		return finishResult(base)
	}
	base.Canary = canary
	canarySum := sha256.Sum256([]byte(canary))
	base.CanaryDigest = hex.EncodeToString(canarySum[:])

	payload := j.Tmpl.Render(canary)
	req, err := buildRequest(ctx, j.Target.URL, j.Tmpl, payload, e.Options.MaxBodyBytes)
	if err != nil {
		base.Status = StatusError
		base.Detail = fmt.Sprintf("building request: %v", err)
		return finishResult(base)
	}
	for name, values := range e.Options.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	var requestBytes []byte
	if req.GetBody != nil {
		requestBody, _ := req.GetBody()
		if requestBody != nil {
			requestBytes, _ = io.ReadAll(requestBody)
			requestBody.Close()
		}
	}
	base.Evidence = append(base.Evidence, requestEvidence(req, requestBytes, probeID, canary))

	if e.Options.DryRun {
		base.Status = StatusDryRun
		base.Detail = fmt.Sprintf("[dry-run] would send %s %s", req.Method, redact.URL(req.URL.String(), canary))
		return finishResult(base)
	}

	resp, err := e.doRequest(req)
	if err != nil {
		base.Status = StatusError
		if errors.Is(err, errHostCircuitOpen) || errors.Is(err, context.Canceled) {
			base.Status = StatusBlocked
		}
		base.TransientNetwork = errors.Is(err, errTransientNetwork)
		base.Detail = fmt.Sprintf("sending request to %s: %v", redact.URL(req.URL.String(), canary), redact.Text(err.Error(), canary))
		return finishResult(base)
	}
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		resp.Body.Close()
		base.Status = StatusBlocked
		base.Detail = "redirect response was not followed by scope policy"
		base.SkipReason = base.Detail
		return finishResult(base)
	}
	limit := e.Options.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	responseBytes, truncated, readErr := readBoundedBody(resp.Body, limit)
	resp.Body.Close()
	base.Evidence = append(base.Evidence, responseEvidence(resp, responseBytes, probeID, truncated))
	if readErr != nil {
		base.Status = StatusInconclusive
		base.Detail = "response body could not be read completely"
		return finishResult(base)
	}
	// A response matcher is only a weak hint. It must NOT pre-empt OOB
	// correlation: a valid callback is stronger evidence than any matcher, so
	// I defer the matcher outcome until after the OOB window closes.
	matcherStatus, matcherDetail := classifyResponse(j.Tmpl, resp.StatusCode, responseBytes)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		base.Status = StatusInconclusive
		base.Detail = "response may indicate access control or request filtering; OOB correlation not attempted"
		return finishResult(base)
	}

	// Wait up to the template's timeout for an OOB callback, polling
	// periodically. This is where "confirmed" vs "not vulnerable" is
	// actually decided — never from the HTTP response itself.
	timeout := time.Duration(j.Tmpl.EffectiveTimeout()) * time.Second
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		interaction, err := e.OOB.Poll(ctx, probeID)
		if err != nil {
			base.Status = StatusError
			base.Detail = fmt.Sprintf("polling OOB: %v", err)
			return finishResult(base)
		}
		if interaction != nil && interaction.ProbeID == probeID && interaction.Protocol == j.Tmpl.OOBProtocol {
			base.Status = StatusConfirmed
			base.Evidence = append(base.Evidence, interactionEvidence(interaction, probeID))
			base.Detail = fmt.Sprintf("OOB %s callback received from %s", interaction.Protocol, interaction.SourceIP)
			return finishResult(base)
		}
		select {
		case <-ctx.Done():
			base.Status = StatusInconclusive
			base.Detail = "context cancelled while waiting for callback"
			return finishResult(base)
		case <-time.After(pollInterval):
		}
	}

	// No OOB callback within the window. A matcher that fired is a weak
	// advisory hint (POTENTIAL); otherwise this is a completed negative.
	if matcherStatus != "" {
		base.Status = matcherStatus
		base.Detail = matcherDetail + "; no OOB callback observed within timeout"
		return finishResult(base)
	}
	base.Status = StatusNotVulnerable
	base.Detail = "no OOB callback observed within timeout"
	return finishResult(base)
}

// SetHTTPClient replaces the transport for a locally controlled lab or test.
// Callers remain responsible for preserving the no-redirect policy.
func (e *Engine) SetHTTPClient(client *http.Client) { e.client = client }

// BuildRequest constructs a bounded probe request using only the explicit
// target and validated template. The bodyLimit argument is required so callers
// must choose a body budget explicitly.
func BuildRequest(ctx context.Context, target *url.URL, t *template.Template, payload string, bodyLimit int64) (*http.Request, error) {
	return buildRequest(ctx, target, t, payload, bodyLimit)
}

// RunTarget executes one already-scheduled target/template job. It is useful
// for a reviewed plan; imported endpoints are never converted into targets.
func (e *Engine) RunTarget(ctx context.Context, target scope.Target, tmpl *template.Template) Result {
	return e.runOne(ctx, job{Target: target, Tmpl: tmpl, ID: NewJob(target, tmpl).ID})
}

// buildRequest constructs the single HTTP request for a probe, injecting
// the rendered payload at every location the template specifies.
func buildRequest(ctx context.Context, target *url.URL, t *template.Template, payload string, bodyLimit int64) (*http.Request, error) {
	limit := bodyLimit
	if limit <= 0 || limit > requestbody.MaxBytes {
		limit = requestbody.MaxBytes
	}
	u := *target
	if t.PathTemplate != "" {
		if strings.HasPrefix(t.PathTemplate, "/") || strings.Contains(t.PathTemplate, "..") || strings.Contains(t.PathTemplate, "\\") || strings.ContainsAny(t.PathTemplate, "\r\n") {
			return nil, fmt.Errorf("template path must be relative and cannot contain traversal or control characters")
		}
		u.Path = joinPath(target.Path, t.PathTemplate)
	}

	query := u.Query()
	var bodyParts []string
	jsonBody := map[string]string{}
	var rawPathInjected bool

	for _, ip := range t.InjectionPoints {
		switch ip.Location {
		case "query":
			query.Set(ip.Name, payload)
		case "body":
			if t.BodyContentType == "application/json" {
				jsonBody[ip.Name] = payload
			} else {
				bodyParts = append(bodyParts, fmt.Sprintf("%s=%s", url.QueryEscape(ip.Name), url.QueryEscape(payload)))
			}
		case "path":
			if !rawPathInjected {
				u.Path = strings.Replace(u.Path, "{{inject}}", payload, 1)
				rawPathInjected = true
			}
		}
	}
	u.RawQuery = query.Encode()

	method := t.Method
	if method == "" {
		method = http.MethodGet
	}

	var bodyReader io.Reader
	var typedBody bool
	var bodyContentType string
	var bodyBytes []byte
	if t.BodyContentType == "application/xml" || t.BodyContentType == "text/xml" || t.BodyContentType == "multipart/form-data" {
		mutations := make(map[string]string)
		for _, ip := range t.InjectionPoints {
			if ip.Location == "body" {
				mutations[ip.Name] = payload
			}
		}
		var encoded []byte
		var err error
		if t.BodyContentType == "multipart/form-data" {
			encoded, bodyContentType, err = requestbody.Multipart(t.BodyFields, mutations, t.MultipartBoundary, limit)
		} else {
			encoded, err = requestbody.XML(t.BodyFields, mutations, limit)
			bodyContentType = t.BodyContentType
		}
		if err != nil {
			return nil, fmt.Errorf("encoding typed request body: %w", err)
		}
		bodyBytes = encoded
		typedBody = true
	} else if len(jsonBody) > 0 {
		encoded, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, fmt.Errorf("encoding JSON body: %w", err)
		}
		bodyBytes = encoded
	} else if len(bodyParts) > 0 {
		bodyBytes = []byte(strings.Join(bodyParts, "&"))
	}
	if int64(len(bodyBytes)) > limit {
		return nil, fmt.Errorf("encoded request body exceeds %d-byte limit", limit)
	}
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	// Path-injected payloads (e.g. ${jndi:ldap://...}) must reach the target
	// verbatim. Go's net/url always percent-encodes '{', '}' in a path, even
	// via RawPath, which would corrupt such payloads. Setting Opaque makes the
	// transport write the path+query verbatim; only genuinely illegal bytes
	// (control, space, non-ASCII) are escaped.
	if rawPathInjected {
		opaque := escapePathMinimal(u.Path)
		if u.RawQuery != "" {
			opaque += "?" + u.RawQuery
		}
		req.URL.Opaque = opaque
		req.URL.RawQuery = ""
	}

	for _, ip := range t.InjectionPoints {
		if ip.Location == "header" {
			req.Header.Set(ip.Name, payload)
		}
	}
	if typedBody {
		req.Header.Set("Content-Type", bodyContentType)
	} else if len(bodyParts) > 0 || len(jsonBody) > 0 {
		ct := t.BodyContentType
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		req.Header.Set("Content-Type", ct)
	}
	// The scanner UA is a default, not an override: if a template declares
	// User-Agent as an injection point (e.g. Log4Shell-style header probes),
	// the payload must win. Otherwise the injection is silently dropped.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "rce-finder/0.1 (+authorized-security-testing)")
	}

	return req, nil
}

func joinPath(base, extra string) string {
	if extra == "" {
		return base
	}
	if strings.HasPrefix(extra, "/") {
		return extra
	}
	return strings.TrimRight(base, "/") + "/" + extra
}

// escapePathMinimal percent-encodes only bytes that are illegal in a raw
// request path (control characters, space, and non-ASCII). It deliberately
// leaves payload-significant characters ($, {, }, ', :, /, etc.) intact so a
// path-injected payload reaches the target verbatim. '%' is left as-is to
// avoid double-encoding an already-escaped payload.
func escapePathMinimal(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f || c == ' ' || c >= 0x80 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
