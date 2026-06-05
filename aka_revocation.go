package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// revocationOracle reports whether a given attestation cert serial
// has been published by Google as revoked or suspended. Implementations
// must be goroutine-safe; the AKA verifier may call IsRevoked from many
// concurrent requests.
//
// The oracle's data source is
// https://android.googleapis.com/attestation/status — Google's
// published list of attestation keys flagged for known hardware
// compromise. A device whose key Google has flagged still passes
// chain-to-Google verification (the cert is structurally valid;
// only its place on the revocation list is the new signal), so this
// oracle is the cryptographic gate against that.
//
// Returns (revoked=false, dataAvailable=false) when the oracle has
// no fresh data. The verifier treats that as "don't gate on
// revocation for this verify call" — best-effort, not lock-out.
// Honest framing: this is what the Google docs explicitly say to do
// when the revocation list is unreachable.
type revocationOracle interface {
	IsRevoked(serial *big.Int) (revoked bool, dataAvailable bool)
}

// googleRevocationOracle fetches from Google's published list and
// caches in memory. Construction kicks off a pre-warm fetch with a
// short timeout — fast deploys don't pay first-request latency.
// Subsequent stale-cache refreshes are background-attempted at the
// next IsRevoked call; the call still returns from cache so the
// hot path stays free of network latency.
type googleRevocationOracle struct {
	url           string
	httpClient    *http.Client
	cacheTtl      time.Duration
	staleAfter    time.Duration

	mu         sync.RWMutex
	entries    map[string]string // hex(serial) -> status ("REVOKED" | "SUSPENDED")
	lastSync   time.Time
	refreshing bool
}

// googleAttestationStatusURL is the well-known endpoint Google
// publishes the AKA revocation list at. Public, no auth.
const googleAttestationStatusURL = "https://android.googleapis.com/attestation/status"

// Sensible defaults: 24h cache TTL matches Google's published
// Cache-Control on the endpoint. staleAfter = 7d means even on a
// week of network outage we keep using last-known-good rather than
// silently disabling the gate.
const (
	defaultRevocationCacheTtl    = 24 * time.Hour
	defaultRevocationStaleAfter  = 7 * 24 * time.Hour
	revocationPreWarmTimeout     = 5 * time.Second
	revocationBackgroundTimeout  = 10 * time.Second
)

// newGoogleRevocationOracle constructs the production oracle and
// fires off a pre-warm fetch. The pre-warm uses a short timeout so
// a slow Google response doesn't block server startup; if it fails
// the cache stays empty and IsRevoked returns dataAvailable=false
// until a later background refresh succeeds.
func newGoogleRevocationOracle() *googleRevocationOracle {
	o := &googleRevocationOracle{
		url:         googleAttestationStatusURL,
		httpClient:  &http.Client{Timeout: revocationBackgroundTimeout},
		cacheTtl:    defaultRevocationCacheTtl,
		staleAfter:  defaultRevocationStaleAfter,
		entries:     nil,
	}
	go o.preWarm()
	return o
}

func (o *googleRevocationOracle) preWarm() {
	ctx, cancel := context.WithTimeout(context.Background(), revocationPreWarmTimeout)
	defer cancel()
	_ = o.fetch(ctx)
}

// IsRevoked checks cached entries. If the cache is stale, kicks off
// a background refresh without blocking the call — the verify hot
// path always returns from cache.
//
// Returns (false, false) when no cache data is available yet. The
// verifier treats that as "don't gate on revocation."
func (o *googleRevocationOracle) IsRevoked(serial *big.Int) (bool, bool) {
	o.mu.RLock()
	entries := o.entries
	lastSync := o.lastSync
	o.mu.RUnlock()

	if entries == nil {
		// Cache never populated. Best-effort: kick a background
		// refresh (in case the pre-warm failed) and report no data.
		o.maybeBackgroundRefresh()
		return false, false
	}

	// Cache populated but stale: still serve from cache, fire a
	// background refresh.
	if time.Since(lastSync) > o.cacheTtl {
		// If even staleAfter elapsed, refuse to trust the cache —
		// fall back to "no data" so the verifier skips the gate
		// rather than running on month-old revocation state.
		if time.Since(lastSync) > o.staleAfter {
			o.maybeBackgroundRefresh()
			return false, false
		}
		o.maybeBackgroundRefresh()
	}

	// Normalize serial encoding: lowercase hex, no leading zeros
	// preserved (matches what's in Google's JSON keys).
	key := strings.ToLower(serial.Text(16))
	status, ok := entries[key]
	if !ok {
		return false, true
	}
	// Both REVOKED and SUSPENDED block — SUSPENDED is "Google's
	// not sure but you should treat it as bad until we figure it
	// out," which from the issuer's perspective is the same thing.
	return status == "REVOKED" || status == "SUSPENDED", true
}

func (o *googleRevocationOracle) maybeBackgroundRefresh() {
	o.mu.Lock()
	if o.refreshing {
		o.mu.Unlock()
		return
	}
	o.refreshing = true
	o.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), revocationBackgroundTimeout)
		defer cancel()
		_ = o.fetch(ctx)
		o.mu.Lock()
		o.refreshing = false
		o.mu.Unlock()
	}()
}

// fetch performs the actual HTTP GET + JSON parse. Updates the
// cache on success; leaves it alone on failure (last-known-good
// stays valid for staleAfter).
func (o *googleRevocationOracle) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d from %s", resp.StatusCode, o.url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	parsed, err := parseRevocationStatus(body)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	o.mu.Lock()
	o.entries = parsed
	o.lastSync = time.Now()
	o.mu.Unlock()
	return nil
}

// revocationStatusBody mirrors Google's response shape. Top-level
// "entries" maps lowercase-hex serials to per-entry status objects.
// We only need the status field; other fields (reason, comment,
// expires) are kept for human audit but unused at gate time.
type revocationStatusBody struct {
	Entries map[string]struct {
		Status  string `json:"status"`
		Reason  string `json:"reason,omitempty"`
		Comment string `json:"comment,omitempty"`
		Expires string `json:"expires,omitempty"`
	} `json:"entries"`
}

func parseRevocationStatus(body []byte) (map[string]string, error) {
	var doc revocationStatusBody
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Entries))
	for k, v := range doc.Entries {
		out[strings.ToLower(k)] = v.Status
	}
	return out, nil
}

// ─── Test helpers ─────────────────────────────────────────────────

// noopRevocationOracle returns dataAvailable=false for every query.
// Used in tests where we don't care about revocation, and as the
// implicit oracle when an AKA verifier is constructed without one.
type noopRevocationOracle struct{}

func (noopRevocationOracle) IsRevoked(*big.Int) (bool, bool) { return false, false }

// staticRevocationOracle is the test-injection seam: pre-seed a set
// of revoked serials, queries against them return revoked=true with
// dataAvailable=true.
type staticRevocationOracle struct {
	revoked map[string]string
}

func newStaticRevocationOracle(revokedSerialsHex ...string) *staticRevocationOracle {
	m := make(map[string]string, len(revokedSerialsHex))
	for _, s := range revokedSerialsHex {
		m[strings.ToLower(s)] = "REVOKED"
	}
	return &staticRevocationOracle{revoked: m}
}

func (s *staticRevocationOracle) IsRevoked(serial *big.Int) (bool, bool) {
	_, ok := s.revoked[strings.ToLower(serial.Text(16))]
	return ok, true
}

// serialHex is a convenience for tests that need to construct
// expected revocation entries from a *big.Int serial.
func serialHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}

var _ = serialHex // keep available for future test writers
