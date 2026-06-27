package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Requests up to the limit are allowed.
func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 5; i++ {
		d := rl.Allow("alice", 5, time.Hour)
		if !d.Allowed {
			t.Fatalf("request %d/5 should be allowed", i+1)
		}
	}
}

// The first request past the limit is blocked and carries a positive RetryAfter.
func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}
	d := rl.Allow("alice", 5, time.Hour)
	if d.Allowed {
		t.Fatalf("request 6/5 should be blocked")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("blocked decision must include positive RetryAfter, got %v", d.RetryAfter)
	}
}

// Each key has its own budget: exhausting one leaves another unaffected.
func TestRateLimiterIsolatesKeys(t *testing.T) {

	rl := newRateLimiter()
	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}
	if rl.Allow("alice", 5, time.Hour).Allowed {
		t.Fatalf("alice should be blocked")
	}
	if !rl.Allow("bob", 5, time.Hour).Allowed {
		t.Fatalf("bob should be allowed — different key")
	}
}

// A key stays blocked within the window and is allowed once the oldest
// hits age out past it.
func TestRateLimiterWindowSlides(t *testing.T) {

	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	currentTime := base
	rl.now = func() time.Time { return currentTime } // inject a movable clock

	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}

	currentTime = base.Add(30 * time.Minute)
	if rl.Allow("alice", 5, time.Hour).Allowed {
		t.Fatalf("alice still over limit at +30min")
	}

	currentTime = base.Add(time.Hour + time.Second)
	d := rl.Allow("alice", 5, time.Hour)
	if !d.Allowed {
		t.Fatalf("alice should be allowed again past window")
	}
}

// A limit of zero means no limit.
func TestRateLimiterZeroLimitIsUnlimited(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 1000; i++ {
		d := rl.Allow("alice", 0, time.Hour)
		if !d.Allowed {
			t.Fatalf("limit=0 should be unlimited, got block at %d", i)
		}
	}
}

// RetryAfter reflects when the oldest hit leaves the window: blocked 10min in,
// the next slot frees 50min later.
func TestRateLimiterRetryAfterIsAccurate(t *testing.T) {

	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	current := base
	rl.now = func() time.Time { return current } // inject a movable clock

	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}
	current = base.Add(10 * time.Minute)
	d := rl.Allow("alice", 5, time.Hour)
	if d.Allowed {
		t.Fatalf("should still be blocked")
	}

	expected := 50 * time.Minute
	delta := d.RetryAfter - expected
	if delta < -10*time.Second || delta > 10*time.Second {
		t.Fatalf("RetryAfter = %v, want ~%v", d.RetryAfter, expected)
	}
}

// Sweep drops keys whose entire window has aged out, bounding memory.
func TestRateLimiterSweepEvictsCold(t *testing.T) {
	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	current := base
	rl.now = func() time.Time { return current } // inject a movable clock

	rl.Allow("alice", 10, time.Hour)
	if rl.Size() != 1 {
		t.Fatalf("size after first allow = %d, want 1", rl.Size())
	}

	current = base.Add(2 * time.Hour)
	rl.Sweep(time.Hour)
	if rl.Size() != 0 {
		t.Fatalf("expected sweep to evict cold entry; size = %d", rl.Size())
	}
}

// No attestation policy means no issuance limit.
func TestResolveIssuanceLimitNilPolicyIsUnlimited(t *testing.T) {
	if resolveIssuanceLimit(nil) != 0 {
		t.Fatalf("nil policy must be unlimited")
	}
}

// Attestation mode "off" means no issuance limit.
func TestResolveIssuanceLimitOffModeIsUnlimited(t *testing.T) {
	if resolveIssuanceLimit(&AttestationPolicy{Mode: AttestationModeOff}) != 0 {
		t.Fatalf("off mode must be unlimited")
	}
}

// Any active mode without an explicit cap falls back to the default per-hour limit.
func TestResolveIssuanceLimitDefaultsWhenModeSetButLimitAbsent(t *testing.T) {
	for _, mode := range []string{
		AttestationModeObserve, AttestationModeSoft, AttestationModeStrict,
	} {
		got := resolveIssuanceLimit(&AttestationPolicy{Mode: mode})
		if got != defaultMaxIssuancesPerHour {
			t.Errorf("mode %s with no MaxIssuancesPerHour: got %d, want default %d",
				mode, got, defaultMaxIssuancesPerHour)
		}
	}
}

// An explicit MaxIssuancesPerHour overrides the default.
func TestResolveIssuanceLimitHonorsExplicitOverride(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeStrict, MaxIssuancesPerHour: 3}
	if resolveIssuanceLimit(p) != 3 {
		t.Fatalf("expected explicit limit honored")
	}
}

// Once a config's per-hour cap is reached, /v1/issue returns 429 with a
// Retry-After header and a rate_limited error body.
func TestIssueRateLimited(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "observe", "maxIssuancesPerHour": 3}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for i := 0; i < 3; i++ {
		req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
		body, _ := json.Marshal(req)
		resp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("req %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("req %d: status %d, want 200", i+1, resp.StatusCode)
		}
	}

	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("req 4: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("req 4: status %d, want 429", resp.StatusCode)
	}

	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatalf("missing Retry-After header on 429")
	}
	if sec, err := strconv.Atoi(retryAfter); err != nil || sec <= 0 {
		t.Fatalf("Retry-After = %q, want positive integer", retryAfter)
	}

	respBytes, _ := io.ReadAll(resp.Body)
	var errResp IssueError
	if err := json.Unmarshal(respBytes, &errResp); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if errResp.Error != "rate_limited" {
		t.Fatalf("error code = %q, want rate_limited", errResp.Error)
	}
	if errResp.RetryAfter <= 0 {
		t.Fatalf("error body retryAfter = %d, want > 0", errResp.RetryAfter)
	}
}

// The issuance cap is per device key: one device hitting its limit does not
// block another.
func TestIssueRateLimitIsolatesDevices(t *testing.T) {

	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "observe", "maxIssuancesPerHour": 2}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	alice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for i := 0; i < 2; i++ {
		req := buildSignedIssueRequest(t, alice, "AAAAAAAAAAAAAAAAAAAAAA")
		body, _ := json.Marshal(req)
		http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	}

	req := buildSignedIssueRequest(t, alice, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("alice's 3rd should be 429, got %d", resp.StatusCode)
	}

	req2 := buildSignedIssueRequest(t, bob, "AAAAAAAAAAAAAAAAAAAAAA")
	body2, _ := json.Marshal(req2)
	resp2, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body2))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("bob's request should be allowed, got %d", resp2.StatusCode)
	}
}

// A config with no attestation policy is not issuance-limited.
func TestIssueRateLimitOffModeUnlimited(t *testing.T) {

	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for i := 0; i < 20; i++ {
		req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
		body, _ := json.Marshal(req)
		resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("no-policy request %d should be unlimited, got %d", i+1, resp.StatusCode)
		}
	}
}
