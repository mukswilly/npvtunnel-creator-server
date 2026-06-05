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

// ──────────────────────────────────────────────────────────────────
// Pure rateLimiter mechanics
// ──────────────────────────────────────────────────────────────────

func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 5; i++ {
		d := rl.Allow("alice", 5, time.Hour)
		if !d.Allowed {
			t.Fatalf("request %d/5 should be allowed", i+1)
		}
	}
}

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

func TestRateLimiterIsolatesKeys(t *testing.T) {
	// alice hits the limit; bob is unaffected.
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

func TestRateLimiterWindowSlides(t *testing.T) {
	// Fake clock so we can advance time deterministically.
	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	currentTime := base
	rl.now = func() time.Time { return currentTime }

	// Burn through the limit at t=0.
	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}
	// Still blocked at t=0+30 min.
	currentTime = base.Add(30 * time.Minute)
	if rl.Allow("alice", 5, time.Hour).Allowed {
		t.Fatalf("alice still over limit at +30min")
	}
	// Once past the 1-hour window (+1h 1s), the oldest of the 5 has dropped
	// off. Allowed should be true.
	currentTime = base.Add(time.Hour + time.Second)
	d := rl.Allow("alice", 5, time.Hour)
	if !d.Allowed {
		t.Fatalf("alice should be allowed again past window")
	}
}

func TestRateLimiterZeroLimitIsUnlimited(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 1000; i++ {
		d := rl.Allow("alice", 0, time.Hour)
		if !d.Allowed {
			t.Fatalf("limit=0 should be unlimited, got block at %d", i)
		}
	}
}

func TestRateLimiterRetryAfterIsAccurate(t *testing.T) {
	// When the limit is hit at t=0 with 5 reqs, the oldest will drop off
	// at t=1h. Asking again at t=10min should report RetryAfter ~= 50min.
	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	current := base
	rl.now = func() time.Time { return current }

	for i := 0; i < 5; i++ {
		rl.Allow("alice", 5, time.Hour)
	}
	current = base.Add(10 * time.Minute)
	d := rl.Allow("alice", 5, time.Hour)
	if d.Allowed {
		t.Fatalf("should still be blocked")
	}
	// Expect ~50 min. Allow ±10s jitter for any nanosecond arithmetic.
	expected := 50 * time.Minute
	delta := d.RetryAfter - expected
	if delta < -10*time.Second || delta > 10*time.Second {
		t.Fatalf("RetryAfter = %v, want ~%v", d.RetryAfter, expected)
	}
}

func TestRateLimiterSweepEvictsCold(t *testing.T) {
	rl := newRateLimiter()
	base := time.Unix(1_700_000_000, 0)
	current := base
	rl.now = func() time.Time { return current }

	// Add an entry for alice.
	rl.Allow("alice", 10, time.Hour)
	if rl.Size() != 1 {
		t.Fatalf("size after first allow = %d, want 1", rl.Size())
	}
	// Advance well past the window and sweep.
	current = base.Add(2 * time.Hour)
	rl.Sweep(time.Hour)
	if rl.Size() != 0 {
		t.Fatalf("expected sweep to evict cold entry; size = %d", rl.Size())
	}
}

// ──────────────────────────────────────────────────────────────────
// resolveIssuanceLimit
// ──────────────────────────────────────────────────────────────────

func TestResolveIssuanceLimitNilPolicyIsUnlimited(t *testing.T) {
	if resolveIssuanceLimit(nil) != 0 {
		t.Fatalf("nil policy must be unlimited")
	}
}

func TestResolveIssuanceLimitOffModeIsUnlimited(t *testing.T) {
	if resolveIssuanceLimit(&AttestationPolicy{Mode: AttestationModeOff}) != 0 {
		t.Fatalf("off mode must be unlimited")
	}
}

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

func TestResolveIssuanceLimitHonorsExplicitOverride(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeStrict, MaxIssuancesPerHour: 3}
	if resolveIssuanceLimit(p) != 3 {
		t.Fatalf("expected explicit limit honored")
	}
}

// ──────────────────────────────────────────────────────────────────
// End-to-end via /v1/issue
// ──────────────────────────────────────────────────────────────────

func TestIssueRateLimited(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "xray-vless-reality",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"$NPVT_CREDENTIAL$"}},
		"attestationPolicy": {"mode": "observe", "maxIssuancesPerHour": 3}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// First 3 requests should succeed.
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

	// 4th should hit 429.
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

	// Retry-After header should be set and parse to a positive integer.
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatalf("missing Retry-After header on 429")
	}
	if sec, err := strconv.Atoi(retryAfter); err != nil || sec <= 0 {
		t.Fatalf("Retry-After = %q, want positive integer", retryAfter)
	}

	// Response body has the rate_limited error code.
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

func TestIssueRateLimitIsolatesDevices(t *testing.T) {
	// alice exhausts her quota; bob's first request still succeeds.
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "xray-vless-reality",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"$NPVT_CREDENTIAL$"}},
		"attestationPolicy": {"mode": "observe", "maxIssuancesPerHour": 2}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	alice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// alice maxes out.
	for i := 0; i < 2; i++ {
		req := buildSignedIssueRequest(t, alice, "AAAAAAAAAAAAAAAAAAAAAA")
		body, _ := json.Marshal(req)
		http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	}
	// alice's third is 429.
	req := buildSignedIssueRequest(t, alice, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("alice's 3rd should be 429, got %d", resp.StatusCode)
	}

	// bob's first request is allowed.
	req2 := buildSignedIssueRequest(t, bob, "AAAAAAAAAAAAAAAAAAAAAA")
	body2, _ := json.Marshal(req2)
	resp2, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body2))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("bob's request should be allowed, got %d", resp2.StatusCode)
	}
}

func TestIssueRateLimitOffModeUnlimited(t *testing.T) {
	// With mode=off, even MANY requests in a row should not be limited.
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "xray-vless-reality",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"$NPVT_CREDENTIAL$"}}
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
