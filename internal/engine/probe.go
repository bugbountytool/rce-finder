// Package engine orchestrates the scan: for every (target, template) pair
// it issues a canary, builds and sends a single non-destructive HTTP
// request carrying the payload, then hands off to the correlator to wait
// for an OOB callback.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/requestbody"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

// Status is the final, deliberately binary (plus error) outcome of a probe.
type Status string

const (
	StatusConfirmed     Status = "CONFIRMED"
	StatusNotVulnerable Status = "NOT_VULNERABLE"
	StatusDryRun        Status = "DRY_RUN"
	StatusSkipped       Status = "SKIPPED"
	StatusBlocked       Status = "BLOCKED"
	StatusError         Status = "ERROR"
)

// Result is the outcome of running one template against one target.
type Result struct {
	ProbeID    string    `json:"probe_id"`
	Target     string    `json:"target"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	References []string  `json:"references,omitempty"`
	Status     Status    `json:"status"`
	Canary     string    `json:"canary,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
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
}

func DefaultOptions() Options {
	return Options{
		Concurrency:      5,
		RequestsPerSec:   2,
		DryRun:           false,
		HTTPTimeout:      10 * time.Second,
		MaxResponseBytes: 1 << 20, // 1 MiB
		MaxBodyBytes:     requestbody.MaxBytes,
		Policy:           policy.Default(),
	}
}

// Engine runs templates against targets.
type Engine struct {
	OOB     oob.Client
	Options Options
	limiter *rateLimiter
	client  *http.Client
}

func New(oobClient oob.Client, opts Options) *Engine {
	if opts.Policy.Mode == "" {
		opts.Policy = policy.Default()
	}
	return &Engine{
		OOB:     oobClient,
		Options: opts,
		limiter: newRateLimiter(opts.RequestsPerSec),
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
type job struct {
	target scope.Target
	tmpl   *template.Template
}

// Run executes every template against every target and streams results to
// the returned channel, closing it when the scan is complete.
func (e *Engine) Run(ctx context.Context, targets []scope.Target, templates []*template.Template) <-chan Result {
	jobs := make(chan job)
	results := make(chan Result)

	go func() {
		defer close(jobs)
		for _, t := range targets {
			for _, tmpl := range templates {
				select {
				case jobs <- job{target: t, tmpl: tmpl}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	workers := e.Options.Concurrency
	if workers < 1 {
		workers = 1
	}

	done := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range jobs {
				e.limiter.Wait(ctx)
				r := e.runOne(ctx, j)
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		for i := 0; i < workers; i++ {
			<-done
		}
		close(results)
	}()

	return results
}

func (e *Engine) runOne(ctx context.Context, j job) Result {
	started := time.Now()
	probeID := uuid.NewString()

	base := Result{
		ProbeID:    probeID,
		Target:     j.target.Raw,
		TemplateID: j.tmpl.ID,
		Name:       j.tmpl.Name,
		Severity:   string(j.tmpl.Severity),
		References: j.tmpl.References,
		StartedAt:  started,
	}
	if !e.Options.Policy.AllowsTemplate(policy.Mode(j.tmpl.Mode)) {
		base.Status = StatusSkipped
		base.Detail = fmt.Sprintf("template requires %s mode; scan policy is %s", j.tmpl.Mode, e.Options.Policy.Mode)
		base.FinishedAt = time.Now()
		return base
	}

	canary, err := e.OOB.Issue(ctx, probeID)
	if err != nil {
		base.Status = StatusError
		base.Detail = fmt.Sprintf("issuing canary: %v", err)
		base.FinishedAt = time.Now()
		return base
	}
	base.Canary = canary

	payload := j.tmpl.Render(canary)
	req, err := buildRequest(ctx, j.target.URL, j.tmpl, payload, e.Options.MaxBodyBytes)
	if err != nil {
		base.Status = StatusError
		base.Detail = fmt.Sprintf("building request: %v", err)
		base.FinishedAt = time.Now()
		return base
	}
	for name, values := range e.Options.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	if e.Options.DryRun {
		base.Status = StatusDryRun
		base.Detail = fmt.Sprintf("[dry-run] would send %s %s", req.Method, req.URL.String())
		base.FinishedAt = time.Now()
		return base
	}

	resp, err := e.client.Do(req)
	if err != nil {
		base.Status = StatusError
		base.Detail = fmt.Sprintf("sending request: %v", err)
		base.FinishedAt = time.Now()
		return base
	}
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		resp.Body.Close()
		base.Status = StatusBlocked
		base.Detail = fmt.Sprintf("redirect to %q was not followed by scope policy", resp.Header.Get("Location"))
		base.FinishedAt = time.Now()
		return base
	}
	limit := e.Options.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	resp.Body.Close()

	// Wait up to the template's timeout for an OOB callback, polling
	// periodically. This is where "confirmed" vs "not vulnerable" is
	// actually decided — never from the HTTP response itself.
	timeout := time.Duration(j.tmpl.TimeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		interaction, err := e.OOB.Poll(ctx, probeID)
		if err != nil {
			base.Status = StatusError
			base.Detail = fmt.Sprintf("polling OOB: %v", err)
			base.FinishedAt = time.Now()
			return base
		}
		if interaction != nil && interaction.ProbeID == probeID && interaction.Protocol == j.tmpl.OOBProtocol {
			base.Status = StatusConfirmed
			base.Detail = fmt.Sprintf("OOB %s callback received from %s", interaction.Protocol, interaction.SourceIP)
			base.FinishedAt = time.Now()
			return base
		}
		select {
		case <-ctx.Done():
			base.Status = StatusError
			base.Detail = "context cancelled while waiting for callback"
			base.FinishedAt = time.Now()
			return base
		case <-time.After(pollInterval):
		}
	}

	base.Status = StatusNotVulnerable
	base.Detail = "no OOB callback observed within timeout"
	base.FinishedAt = time.Now()
	return base
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
	return e.runOne(ctx, job{target: target, tmpl: tmpl})
}

// buildRequest constructs the single HTTP request for a probe, injecting
// the rendered payload at every location the template specifies.
func buildRequest(ctx context.Context, target *url.URL, t *template.Template, payload string, bodyLimit ...int64) (*http.Request, error) {
	limit := requestbody.MaxBytes
	if len(bodyLimit) > 0 {
		limit = bodyLimit[0]
	}
	u := *target
	if t.PathTemplate != "" {
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
		bodyReader = bytes.NewReader(encoded)
		typedBody = true
	} else if len(jsonBody) > 0 {
		encoded, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, fmt.Errorf("encoding JSON body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	} else if len(bodyParts) > 0 {
		bodyReader = bytes.NewBufferString(strings.Join(bodyParts, "&"))
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
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
	req.Header.Set("User-Agent", "rce-finder/0.1 (+authorized-security-testing)")

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
