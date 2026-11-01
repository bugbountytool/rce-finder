package engine

import (
	"context"
	"sync"
	"time"
)

// rateLimiter serializes request start times and is cancellation-aware.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(perSecond float64) *rateLimiter {
	if perSecond <= 0 {
		perSecond = 1
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()
	start := now
	if r.next.After(now) {
		start = r.next
	}
	r.next = start.Add(r.interval)
	r.mu.Unlock()
	if wait := time.Until(start); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
