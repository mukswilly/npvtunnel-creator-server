package main

import (
	"sync"
	"time"
)

// rateLimiter is a sliding-window limiter keyed by an arbitrary string. Each key
// holds the timestamps of recent events within the window. now is a clock seam
// for tests.
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*[]time.Time
	now     func() time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		entries: make(map[string]*[]time.Time),
		now:     time.Now,
	}
}

// rateLimitDecision is the result of Allow. RetryAfter is set only when the
// request was denied.
type rateLimitDecision struct {
	Allowed bool

	RetryAfter time.Duration
}

// Allow records an event for key and reports whether it is within limit over the
// trailing window. A non-positive limit disables limiting. When denied,
// RetryAfter is how long until the oldest in-window event ages out (at least one
// second).
func (r *rateLimiter) Allow(key string, limit int, window time.Duration) rateLimitDecision {
	if limit <= 0 {
		return rateLimitDecision{Allowed: true}
	}
	now := r.now()
	cutoff := now.Add(-window)

	r.mu.Lock()
	defer r.mu.Unlock()

	bucket, ok := r.entries[key]
	if !ok {
		fresh := make([]time.Time, 0, limit+1)
		bucket = &fresh
		r.entries[key] = bucket
	}

	// Drop events that have aged out of the window (in place).
	trimmed := (*bucket)[:0]
	for _, ts := range *bucket {
		if ts.After(cutoff) {
			trimmed = append(trimmed, ts)
		}
	}
	*bucket = trimmed

	if len(*bucket) >= limit {

		oldest := (*bucket)[0]
		retryAfter := oldest.Add(window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return rateLimitDecision{Allowed: false, RetryAfter: retryAfter}
	}

	*bucket = append(*bucket, now)
	return rateLimitDecision{Allowed: true}
}

// Sweep deletes keys whose events have all aged out of the window, bounding
// memory for one-off callers.
func (r *rateLimiter) Sweep(window time.Duration) {
	cutoff := r.now().Add(-window)

	r.mu.Lock()
	defer r.mu.Unlock()

	for key, bucket := range r.entries {
		hasRecent := false
		for _, ts := range *bucket {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(r.entries, key)
		}
	}
}

// Size returns the number of tracked keys.
func (r *rateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
