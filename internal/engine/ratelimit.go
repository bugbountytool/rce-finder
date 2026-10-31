package engine

import (
	"context"
	"sync"
	"time"
)

// rateLimiter is a simple token-bucket limiter so scans default to a
// conservative request rate rather than hammering targets.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func newRateLimiter(perSecond float64) *rateLimiter {
	if perSecond <= 0 {
		perSecond = 1
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

func (r *rateLimiter) Wait(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	next := r.last.Add(r.interval)
	if next.After(now) {
		select {
		case <-time.After(next.Sub(now)):
		case <-ctx.Done():
		}
		r.last = next
	} else {
		r.last = now
	}
}
