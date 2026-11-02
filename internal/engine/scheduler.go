package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/redact"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

// ProgressEvent is a redacted scheduler event. It contains identifiers and
// statuses only, never headers, cookies, request bodies, or canaries.
type ProgressEvent struct {
	ScanID     string    `json:"scan_id"`
	JobID      string    `json:"job_id"`
	TemplateID string    `json:"template_id"`
	Target     string    `json:"target"`
	Event      string    `json:"event"`
	Status     Status    `json:"status,omitempty"`
	Attempt    int       `json:"attempt,omitempty"`
	At         time.Time `json:"at"`
}

type hostState struct {
	mu        sync.Mutex
	limiter   *rateLimiter
	errors    int
	blocked   bool
	requests  int
	admission sync.Mutex
}

func (e *Engine) host(key string) *hostState {
	e.hostsMu.Lock()
	defer e.hostsMu.Unlock()
	h := e.hosts[key]
	if h == nil {
		h = &hostState{limiter: newRateLimiter(e.Options.PerHostRPS)}
		e.hosts[key] = h
	}
	return h
}

func (h *hostState) reserve(ctx context.Context, budget int) error {
	h.mu.Lock()
	if h.blocked {
		h.mu.Unlock()
		return errHostCircuitOpen
	}
	h.mu.Unlock()
	h.limiter.Wait(ctx)
	return ctx.Err()
}

func (h *hostState) recordNetworkError(budget int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errors++
	if budget > 0 && h.errors >= budget {
		h.blocked = true
	}
}

func (h *hostState) reset() {
	h.mu.Lock()
	h.errors = 0
	h.mu.Unlock()
}

func (h *hostState) isBlocked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.blocked
}

var errHostCircuitOpen = errors.New("host circuit breaker is open after transient network errors")
var errTransientNetwork = errors.New("transient network error")

// Job is a deterministic unit of reviewed work. Shape includes the rendered
// request shape but not its per-run canary, so equivalent work deduplicates.
type Job struct {
	ID     string
	Target scope.Target
	Tmpl   *template.Template
}

func NewJob(target scope.Target, tmpl *template.Template) Job {
	canonical := struct {
		Target   string
		ID       string
		Method   string
		Path     string
		Body     string
		Payload  string
		Boundary string
		Fields   []string
		Points   []template.InjectionPoint
	}{target.Raw, tmpl.ID, tmpl.Method, tmpl.PathTemplate, tmpl.BodyContentType, tmpl.PayloadTemplate, tmpl.MultipartBoundary, nil, tmpl.InjectionPoints}
	for _, field := range tmpl.BodyFields {
		canonical.Fields = append(canonical.Fields, field.Name+"\x00"+field.Value+"\x00"+field.Type)
	}
	data, _ := json.Marshal(canonical)
	digest := sha256.Sum256(data)
	return Job{ID: hex.EncodeToString(digest[:16]), Target: target, Tmpl: tmpl}
}

// Jobs returns deterministic, deduplicated target/template work.
func Jobs(targets []scope.Target, templates []*template.Template) []Job {
	seen := make(map[string]bool)
	var jobs []Job
	for _, target := range targets {
		for _, tmpl := range templates {
			job := NewJob(target, tmpl)
			if seen[job.ID] {
				continue
			}
			seen[job.ID] = true
			jobs = append(jobs, job)
		}
	}
	return jobs
}

// RunJobs executes reviewed jobs and emits redacted lifecycle events.
func (e *Engine) RunJobs(ctx context.Context, jobs []Job) <-chan Result {
	queue := make(chan Job)
	results := make(chan Result)
	workers := e.Options.Concurrency
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for job := range queue {
				if ctx.Err() != nil {
					result := e.failedJob(job, StatusBlocked, "scan cancelled before request")
					results <- result
					continue
				}
				e.progress(job, "started", "", 0)
				result := e.runJob(ctx, job)
				results <- result
				e.progress(job, "finished", result.Status, 0)
			}
		}()
	}
	go func() {
		defer close(queue)
		for _, job := range jobs {
			queue <- job
		}
	}()
	go func() { wg.Wait(); close(results) }()
	return results
}

func (e *Engine) progress(job Job, event string, status Status, attempt int) {
	if e.Options.Progress == nil {
		return
	}
	e.Options.Progress(ProgressEvent{ScanID: e.Options.ScanID, JobID: job.ID, TemplateID: job.Tmpl.ID, Target: redact.URL(job.Target.Raw), Event: event, Status: status, Attempt: attempt, At: time.Now().UTC()})
}

func (e *Engine) runJob(ctx context.Context, job Job) Result {
	for attempt := 0; ; attempt++ {
		host := e.host(job.Target.URL.Host)
		host.admission.Lock()
		if err := host.reserve(ctx, e.Options.HostErrorBudget); err != nil {
			host.admission.Unlock()
			return e.failedJob(job, StatusBlocked, "host error budget exhausted or scan cancelled")
		}
		if err := e.limiter.Wait(ctx); err != nil {
			host.admission.Unlock()
			return e.failedJob(job, StatusBlocked, "scan cancelled while waiting for rate limit")
		}
		if err := ctx.Err(); err != nil {
			host.admission.Unlock()
			return e.failedJob(job, StatusBlocked, "scan cancelled before request")
		}
		result := e.runOne(ctx, job)
		host.admission.Unlock()
		result = finishResult(result)
		result.Status = result.Classification
		transient := result.TransientNetwork
		result.TransientNetwork = false
		if result.Status == StatusError && transient {
			host.recordNetworkError(e.Options.HostErrorBudget)
			if attempt < e.Options.MaxRetries && !host.isBlocked() {
				e.progress(job, "retry", StatusError, attempt+1)
				backoff := e.Options.RetryBackoff * time.Duration(1<<attempt)
				if backoff > 5*time.Second {
					backoff = 5 * time.Second
				}
				timer := time.NewTimer(backoff)
				select {
				case <-timer.C:
					continue
				case <-ctx.Done():
					timer.Stop()
					return e.failedJob(job, StatusBlocked, "scan cancelled during retry backoff")
				}
			}
		} else if result.Status != StatusError {
			host.reset()
		}
		return result
	}
}

func (e *Engine) failedJob(job Job, status Status, detail string) Result {
	now := time.Now()
	return finishResult(Result{ProbeID: uuid.NewString(), ScanID: e.Options.ScanID, JobID: job.ID, Target: redact.URL(job.Target.Raw), TemplateID: job.Tmpl.ID, Name: job.Tmpl.Name, Severity: string(job.Tmpl.Severity), References: job.Tmpl.References, Status: status, Detail: detail, StartedAt: now, FinishedAt: now})
}

func (e *Engine) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := e.client.Do(req)
	if err != nil && isTransientNetworkError(err) {
		return nil, fmt.Errorf("%w: %v", errTransientNetwork, err)
	}
	return resp, err
}

func isTransientNetworkError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// PolicyFingerprint includes non-secret execution/trust choices that affect
// whether a saved outcome can be reused. Credentials are never fingerprinted.
func PolicyFingerprint(p policy.Policy, allowUnsigned bool) string {
	return digestJSON(struct {
		Mode             policy.Mode
		AllowPrivate     bool
		AllowCredentials bool
		AllowUnsigned    bool
	}{p.Mode, p.AllowPrivate, p.AllowCredentials, allowUnsigned})
}

// ScopeFingerprint covers every explicit target, not imported metadata.
func ScopeFingerprint(targets []scope.Target) string {
	items := make([]string, len(targets))
	for i, target := range targets {
		items[i] = target.Raw
	}
	sort.Strings(items)
	return digestJSON(items)
}

func TemplateFingerprint(templates []*template.Template) string {
	type entry struct {
		ID     string
		SHA256 string
	}
	var entries []entry
	for _, tmpl := range templates {
		entries = append(entries, entry{ID: tmpl.ID, SHA256: digestJSON(tmpl)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return digestJSON(entries)
}

func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidatePlan ensures an imported/reviewed plan still matches explicit scope
// and template policy. It performs no network I/O.
func ValidatePlan(targets []scope.Target, templates []*template.Template, p policy.Policy) error {
	if len(targets) == 0 || len(templates) == 0 {
		return fmt.Errorf("reviewed plan requires explicit targets and templates")
	}
	for _, target := range targets {
		if err := p.ValidateTarget(target.URL); err != nil {
			return err
		}
	}
	for _, tmpl := range templates {
		if err := tmpl.Validate(); err != nil {
			return err
		}
	}
	return nil
}
