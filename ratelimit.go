package main

import (
	"sync"
	"time"
)

// rateLimiter is an in-memory sliding-window counter keyed by devicePk.
//
// For each key it tracks the timestamps of recent allowed requests.
// On Allow(key, limit, window), it drops timestamps older than `window`
// and checks whether (count + 1) <= limit. If so, records the new
// timestamp and returns true. Otherwise returns false plus a retry-
// after duration based on when the oldest in-window request would
// drop off.
//
// Why sliding-window instead of token-bucket: the audit story is simpler
// (each "you got rate-limited" event in the log has a clear "you made
// N requests in window W" interpretation). Token-bucket smooths bursts
// but the burst-tolerance dial doesn't pay off for the abuse pattern
// we care about, which is "one device, many issuances over a short
// period."
//
// Memory bound: entries with no activity within `window` are evicted on
// the next call that touches the same key. A separate background sweep
// (Sweep, called periodically by the caller) evicts entries across all
// keys. For a typical creator with O(100s) of recipients each hitting
// the issuer once per hour, the total entry count stays well-bounded
// without the sweep, but the sweep is cheap insurance against
// long-running processes accumulating dead keys from one-off devices.
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

// rateLimitDecision is what Allow returns.
type rateLimitDecision struct {
	// Allowed reports whether the request should proceed.
	Allowed bool
	// RetryAfter is set when Allowed is false. The smallest duration
	// the caller can wait before re-trying and getting Allowed = true,
	// assuming no further requests fail in the meantime. Always > 0
	// when Allowed is false; zero when Allowed is true.
	RetryAfter time.Duration
}

// Allow checks whether one more request from `key` within the trailing
// `window` would keep its count at or below `limit`. If so, records the
// new timestamp and returns Allowed = true.
//
// limit <= 0 means "no limit" — always allow. Used by the handler to
// short-circuit when the creator's policy hasn't configured one.
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

	// Drop timestamps older than the window.
	trimmed := (*bucket)[:0]
	for _, ts := range *bucket {
		if ts.After(cutoff) {
			trimmed = append(trimmed, ts)
		}
	}
	*bucket = trimmed

	if len(*bucket) >= limit {
		// Time until the oldest in-window entry drops off — the soonest
		// the caller could try again successfully.
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

// Sweep evicts entries with no activity within `window`. Cheap relative
// to a goroutine-per-entry approach; suitable to call from a ticker or
// from the request path opportunistically.
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

// Size returns the number of tracked keys. Test affordance.
func (r *rateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
