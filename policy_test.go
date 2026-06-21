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
	"strings"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────
// Pure-function: evaluateAttestationPolicy / chooseTtl truth table
// ──────────────────────────────────────────────────────────────────

func TestPolicyOffIgnoresAttestation(t *testing.T) {
	for _, att := range []AttestationBlob{
		{Platform: "NONE", Token: "", Nonce: "n"},
		{Platform: "ANDROID", Token: "tok", Nonce: "n"},
	} {
		d := evaluateAttestationPolicy(nil, att, nil, defaultConfigTtl)
		if d.reject {
			t.Fatalf("nil policy must not reject: %+v", att)
		}
		if d.ttl != defaultConfigTtl {
			t.Fatalf("nil policy must use defaultConfigTtl, got %v", d.ttl)
		}
	}
	d := evaluateAttestationPolicy(&AttestationPolicy{Mode: AttestationModeOff}, AttestationBlob{Platform: "NONE"}, nil, defaultConfigTtl)
	if d.reject || d.ttl != defaultConfigTtl {
		t.Fatalf("off mode must be no-op, got %+v", d)
	}
}

func TestPolicyObserveLogsButDoesNotBlock(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeObserve}
	for _, att := range []AttestationBlob{
		{Platform: "NONE"},
		{Platform: "ANDROID", Token: "tok"},
	} {
		d := evaluateAttestationPolicy(p, att, nil, defaultConfigTtl)
		if d.reject {
			t.Fatalf("observe must not reject: %+v", att)
		}
		if !d.logAttestation {
			t.Fatalf("observe must request logging: %+v", att)
		}
		if d.ttl != defaultConfigTtl {
			t.Fatalf("observe must use defaultConfigTtl, got %v", d.ttl)
		}
	}
}

func TestPolicySoftShortensTtlWhenUnattested(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeSoft, SoftFailureTtlSec: 60}
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "NONE"}, nil, defaultConfigTtl)
	if d.reject {
		t.Fatalf("soft must not reject unattested: %+v", d)
	}
	if d.ttl != 60*time.Second {
		t.Fatalf("soft + unattested + ttlOverride=60: ttl = %v, want 60s", d.ttl)
	}
}

func TestPolicySoftUsesDefaultTtlWhenNotConfigured(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeSoft} // SoftFailureTtlSec unset = 0
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "NONE"}, nil, defaultConfigTtl)
	expected := time.Duration(defaultSoftFailureTtlSec) * time.Second
	if d.ttl != expected {
		t.Fatalf("soft + unattested + ttl unset: ttl = %v, want %v", d.ttl, expected)
	}
}

func TestPolicySoftFullTtlWhenAttested(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeSoft, SoftFailureTtlSec: 60}
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "ANDROID", Token: "tok"}, nil, defaultConfigTtl)
	if d.ttl != defaultConfigTtl {
		t.Fatalf("soft + attested: ttl = %v, want full %v", d.ttl, defaultConfigTtl)
	}
}

func TestPolicyStrictRejectsUnattested(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeStrict}
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "NONE"}, nil, defaultConfigTtl)
	if !d.reject {
		t.Fatalf("strict must reject unattested: %+v", d)
	}
}

func TestPolicyStrictAllowsAttested(t *testing.T) {
	p := &AttestationPolicy{Mode: AttestationModeStrict}
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "ANDROID", Token: "tok"}, nil, defaultConfigTtl)
	if d.reject {
		t.Fatalf("strict must allow attested: %+v", d)
	}
	if d.ttl != defaultConfigTtl {
		t.Fatalf("strict + attested: ttl should be full, got %v", d.ttl)
	}
}

func TestClaimsAttestationRequiresBothPlatformAndToken(t *testing.T) {
	if claimsAttestation(AttestationBlob{Platform: "ANDROID", Token: ""}) {
		t.Fatalf("empty token must not count as claim")
	}
	if claimsAttestation(AttestationBlob{Platform: "NONE", Token: "tok"}) {
		t.Fatalf("NONE platform must not count as claim regardless of token")
	}
	if !claimsAttestation(AttestationBlob{Platform: "ANDROID", Token: "tok"}) {
		t.Fatalf("ANDROID + token must count as claim")
	}
	if !claimsAttestation(AttestationBlob{Platform: "IOS", Token: "tok"}) {
		t.Fatalf("IOS + token must count as claim")
	}
}

// ──────────────────────────────────────────────────────────────────
// Load-time validation
// ──────────────────────────────────────────────────────────────────

func TestConfigsFileRejectsInvalidAttestationMode(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "strikt"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on invalid mode")
	}
	if !strings.Contains(err.Error(), "off|observe|soft|strict") {
		t.Fatalf("expected mode-list message, got: %v", err)
	}
}

func TestConfigsFileRejectsNegativeSoftFailureTtl(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "soft", "softFailureTtlSec": -5}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on negative ttl")
	}
}

func TestConfigsFileAcceptsAllValidModes(t *testing.T) {
	for _, mode := range []string{
		AttestationModeOff, AttestationModeObserve,
		AttestationModeSoft, AttestationModeStrict,
	} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			// Each mode-iteration runs in its own t.TempDir() so the same
			// configId across modes doesn't collide at load time.
			raw := `[{
				"configId": "AAAAAAAAAAAAAAAAAAAAAA",
				"config": {"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}},
				"attestationPolicy": {"mode": "` + mode + `"}
			}]`
			os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
			_, err := NewStateWithDir(dir)
			if err != nil {
				t.Fatalf("mode %q should be accepted: %v", mode, err)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────
// End-to-end: enforcement at /v1/issue
// ──────────────────────────────────────────────────────────────────

func TestIssueStrictModeRejectsRequestWithoutAttestation(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "strict"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// buildSignedIssueRequest defaults to AttestationPlatform "NONE" + empty token.
	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 strict-rejected, got %d: %s", httpResp.StatusCode, respBytes)
	}
	if !strings.Contains(string(respBytes), "attestation_failed") {
		t.Fatalf("expected attestation_failed code, got: %s", respBytes)
	}
}

func TestIssueStrictModeAllowsRequestWithAttestation(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "strict"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	// Override default NONE attestation with a claimed (unverified) token.
	// This mode doesn't verify, just checks presence.
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = "fake-play-integrity-token"
	// Re-sign because attestation.token is in the canonical signing input.
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("expected 200, got %d: %s", httpResp.StatusCode, respBytes)
	}
}

func TestIssueSoftModeShortensTtlForUnattestedRequest(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "soft", "softFailureTtlSec": 60}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)

	before := time.Now().UTC()
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("soft must not reject, got %d: %s", httpResp.StatusCode, respBytes)
	}
	var resp IssueResponse
	json.Unmarshal(respBytes, &resp)

	expires, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiresAt: %v", err)
	}
	gap := expires.Sub(before)
	// Should be ~60 seconds, generously bounded to handle test scheduler jitter.
	if gap < 30*time.Second || gap > 90*time.Second {
		t.Fatalf("expected ~60s TTL for soft+unattested, got %v", gap)
	}
}

func TestIssueOffModeUsesFullTtlRegardlessOfAttestation(t *testing.T) {
	dir := t.TempDir()
	// No attestationPolicy field = "off" by default.
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)

	before := time.Now().UTC()
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	var resp IssueResponse
	json.Unmarshal(respBytes, &resp)
	expires, _ := time.Parse(time.RFC3339, resp.ExpiresAt)

	gap := expires.Sub(before)
	// defaultConfigTtl is 1 hour.
	if gap < 50*time.Minute || gap > 70*time.Minute {
		t.Fatalf("expected ~1h TTL with no policy, got %v", gap)
	}
}

// ──────────────────────────────────────────────────────────────────
// Configurable config TTL (configTtlSec)
// ──────────────────────────────────────────────────────────────────

func TestResolveConfigTtl(t *testing.T) {
	if got := resolveConfigTtl(nil); got != defaultConfigTtl {
		t.Fatalf("nil entry: got %v, want default %v", got, defaultConfigTtl)
	}
	if got := resolveConfigTtl(&ConfigEntry{}); got != defaultConfigTtl {
		t.Fatalf("ConfigTtlSec unset: got %v, want default %v", got, defaultConfigTtl)
	}
	if got := resolveConfigTtl(&ConfigEntry{ConfigTtlSec: 7200}); got != 2*time.Hour {
		t.Fatalf("ConfigTtlSec=7200: got %v, want 2h", got)
	}
}

// A custom baseline propagates through every "full TTL" outcome.
func TestPolicyHonorsBaseTtl(t *testing.T) {
	base := 3 * time.Hour
	cases := []struct {
		name   string
		policy *AttestationPolicy
		att    AttestationBlob
	}{
		{"nil-policy", nil, AttestationBlob{Platform: "NONE"}},
		{"off", &AttestationPolicy{Mode: AttestationModeOff}, AttestationBlob{Platform: "NONE"}},
		{"observe", &AttestationPolicy{Mode: AttestationModeObserve}, AttestationBlob{Platform: "NONE"}},
		{"soft-attested", &AttestationPolicy{Mode: AttestationModeSoft}, AttestationBlob{Platform: "ANDROID", Token: "tok"}},
		{"strict-attested", &AttestationPolicy{Mode: AttestationModeStrict}, AttestationBlob{Platform: "ANDROID", Token: "tok"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := evaluateAttestationPolicy(tc.policy, tc.att, nil, base)
			if d.reject {
				t.Fatalf("unexpected reject: %+v", d)
			}
			if d.ttl != base {
				t.Fatalf("ttl = %v, want baseTtl %v", d.ttl, base)
			}
		})
	}
}

// The soft-mode penalty shortens but never lengthens the baseline: when
// the baseline is shorter than the soft-failure value, the baseline wins.
func TestPolicySoftFailureCappedAtBaseTtl(t *testing.T) {
	base := 2 * time.Minute
	// SoftFailureTtlSec (5m) deliberately larger than the baseline.
	p := &AttestationPolicy{Mode: AttestationModeSoft, SoftFailureTtlSec: 300}
	d := evaluateAttestationPolicy(p, AttestationBlob{Platform: "NONE"}, nil, base)
	if d.ttl != base {
		t.Fatalf("soft+unattested with short baseline: ttl = %v, want capped at %v", d.ttl, base)
	}
}

func TestConfigsFileRejectsConfigTtlBelowFloor(t *testing.T) {
	assertConfigTtlLoadError(t, 30) // floor is 60
}

func TestConfigsFileRejectsConfigTtlAboveCeiling(t *testing.T) {
	assertConfigTtlLoadError(t, int(configTtlMax.Seconds())+1)
}

func TestConfigsFileRejectsNegativeConfigTtl(t *testing.T) {
	assertConfigTtlLoadError(t, -1)
}

func TestConfigsFileAcceptsValidConfigTtl(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"configTtlSec": 7200
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("valid configTtlSec=7200 should load: %v", err)
	}
}

// assertConfigTtlLoadError writes a configs.json with the given configTtlSec
// and asserts NewStateWithDir refuses it with a configTtlSec-naming error.
func assertConfigTtlLoadError(t *testing.T, sec int) {
	t.Helper()
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"configTtlSec": ` + strconv.Itoa(sec) + `
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on configTtlSec=%d", sec)
	}
	if !strings.Contains(err.Error(), "configTtlSec") {
		t.Fatalf("expected configTtlSec message, got: %v", err)
	}
}

// End-to-end: a configured configTtlSec drives the issued expiresAt.
func TestIssueHonorsConfiguredConfigTtl(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"configTtlSec": 7200
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)

	before := time.Now().UTC()
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", httpResp.StatusCode, respBytes)
	}
	var resp IssueResponse
	json.Unmarshal(respBytes, &resp)
	expires, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiresAt %q: %v", resp.ExpiresAt, err)
	}

	gap := expires.Sub(before)
	// configTtlSec=7200 → ~2h, allowing slack for request processing.
	if gap < 110*time.Minute || gap > 130*time.Minute {
		t.Fatalf("expected ~2h TTL from configTtlSec=7200, got %v", gap)
	}
}
