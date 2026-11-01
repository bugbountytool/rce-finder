package engine_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func schedulerOptions() engine.Options {
	opts := engine.DefaultOptions()
	opts.RequestsPerSec = 10000
	opts.PerHostRPS = 10000
	opts.RetryBackoff = time.Millisecond
	return opts
}

func collect(results <-chan engine.Result) []engine.Result {
	var out []engine.Result
	for result := range results {
		out = append(out, result)
	}
	return out
}

func TestDuplicateJobsExecuteOnce(t *testing.T) {
	var calls atomic.Int32
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	jobs := engine.Jobs([]scope.Target{testTarget(), testTarget()}, []*template.Template{testTemplate(), testTemplate()})
	if len(jobs) != 1 {
		t.Fatalf("deduplicated jobs = %d, want 1", len(jobs))
	}
	results := collect(eng.RunJobs(context.Background(), jobs))
	if len(results) != 1 || calls.Load() != 1 {
		t.Fatalf("results = %d requests = %d", len(results), calls.Load())
	}
}

func TestRetriesTransientNetworkErrorsOnly(t *testing.T) {
	var calls atomic.Int32
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) < 3 {
			return nil, &net.OpError{Op: "dial", Err: errors.New("local test connection reset")}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	results := collect(eng.RunJobs(context.Background(), engine.Jobs([]scope.Target{testTarget()}, []*template.Template{testTemplate()})))
	if calls.Load() != 3 || len(results) != 1 || results[0].Status != engine.StatusConfirmed {
		t.Fatalf("calls = %d results = %#v", calls.Load(), results)
	}
}

func TestHostErrorBudgetBlocksLaterJobs(t *testing.T) {
	var calls atomic.Int32
	opts := schedulerOptions()
	opts.MaxRetries = 0
	opts.HostErrorBudget = 1
	eng := engine.New(staticOOB{protocol: "dns"}, opts)
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, &net.OpError{Op: "dial", Err: errors.New("local test connection refused")}
	})})
	second := testTemplate()
	second.ID = "second"
	third := testTemplate()
	third.ID = "third"
	jobs := engine.Jobs([]scope.Target{testTarget()}, []*template.Template{testTemplate(), second, third})
	results := collect(eng.RunJobs(context.Background(), jobs))
	if calls.Load() != 1 || len(results) != 3 {
		t.Fatalf("calls = %d results = %#v", calls.Load(), results)
	}
	for _, result := range results[1:] {
		if result.Status != engine.StatusBlocked {
			t.Errorf("circuit-open result = %#v", result)
		}
	}
}

func TestCancellationStopsScheduledWork(t *testing.T) {
	eng := engine.New(staticOOB{protocol: "dns"}, schedulerOptions())
	eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	done := make(chan []engine.Result, 1)
	go func() {
		done <- collect(eng.RunJobs(ctx, engine.Jobs([]scope.Target{testTarget()}, []*template.Template{testTemplate()})))
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}

func TestPolicyAndOOBCorrelationFailuresAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		want     engine.Status
	}{{"OOB", "http", engine.StatusNotVulnerable}} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			eng := engine.New(staticOOB{protocol: tc.protocol}, schedulerOptions())
			eng.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
			})})
			tmpl := testTemplate()
			results := collect(eng.RunJobs(context.Background(), engine.Jobs([]scope.Target{testTarget()}, []*template.Template{tmpl})))
			if calls.Load() > 1 || results[0].Status != tc.want {
				t.Fatalf("calls = %d result = %#v", calls.Load(), results[0])
			}
		})
	}
}
