package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditSaltPersistsAcrossReopen — like the HMAC key, the audit salt
// has to survive restart so devicePk hashes stay correlatable over time.
func TestAuditSaltPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	first, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	firstSalt := append([]byte{}, first.AuditSalt...)

	if _, err := os.Stat(filepath.Join(dir, "audit-salt.bin")); err != nil {
		t.Fatalf("audit-salt.bin not written: %v", err)
	}

	second, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !bytes.Equal(firstSalt, second.AuditSalt) {
		t.Fatalf("audit salt changed across reopen — would invalidate correlation in existing logs")
	}
}

// TestAuditSaltRejectsWrongSize — like the HMAC key, fail loudly on
// corruption rather than silent regeneration.
func TestAuditSaltRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "audit-salt.bin"), make([]byte, 8), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected error on wrong-size audit salt")
	}
}

// TestHashDevicePkIsDeterministic — same input → same hash. Without
// this property, a creator can't correlate events from one device.
func TestHashDevicePkIsDeterministic(t *testing.T) {
	salt := make([]byte, 32)
	rand.Read(salt)
	pk := "AzqK000000000000000000000000000000000000000000"

	first := hashDevicePk(salt, pk)
	second := hashDevicePk(salt, pk)
	if first != second {
		t.Fatalf("hash not deterministic: %q vs %q", first, second)
	}
}

// TestHashDevicePkDiffersAcrossSalts — logs from different
// creator-servers should not cross-link. Same device under different
// salts → different hashes.
func TestHashDevicePkDiffersAcrossSalts(t *testing.T) {
	saltA := make([]byte, 32)
	saltB := make([]byte, 32)
	rand.Read(saltA)
	rand.Read(saltB)
	pk := "AzqK000000000000000000000000000000000000000000"

	hashA := hashDevicePk(saltA, pk)
	hashB := hashDevicePk(saltB, pk)
	if hashA == hashB {
		t.Fatalf("hashes should differ across salts")
	}
}

// TestHashDevicePkDiffersAcrossDevices — different inputs → different
// hashes. (Birthday-bound, but for the input space we care about, fine.)
func TestHashDevicePkDiffersAcrossDevices(t *testing.T) {
	salt := make([]byte, 32)
	rand.Read(salt)
	hashA := hashDevicePk(salt, "device-A-base64")
	hashB := hashDevicePk(salt, "device-B-base64")
	if hashA == hashB {
		t.Fatalf("hashes should differ across devices")
	}
}

// TestHashDevicePkHandlesMalformedInput — defensive: if devicePkB64
// fails to decode, we should still produce a stable hash rather than
// crash or return empty.
func TestHashDevicePkHandlesMalformedInput(t *testing.T) {
	salt := make([]byte, 32)
	rand.Read(salt)

	// Invalid base64 input.
	first := hashDevicePk(salt, "!!!not-base64!!!")
	second := hashDevicePk(salt, "!!!not-base64!!!")
	if first == "" {
		t.Fatalf("expected stable fallback hash even for malformed input")
	}
	if first != second {
		t.Fatalf("malformed-input hash not deterministic: %q vs %q", first, second)
	}
}

// TestAuditEmitNeverLogsRawDevicePk — the load-bearing privacy property.
// The audit log line for a granted issuance must NOT contain the raw
// devicePk anywhere. Captures the actual slog output and greps it.
func TestAuditEmitNeverLogsRawDevicePk(t *testing.T) {
	dir := t.TempDir()
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// Capture slog output to a buffer so we can inspect what got logged.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	srv := NewServer(state, logger)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	io.ReadAll(httpResp.Body)

	logOutput := logBuf.String()
	if strings.Contains(logOutput, devPkB64) {
		t.Fatalf("audit log contains raw devicePk %q:\n%s", devPkB64, logOutput)
	}
	// Sanity: the hashed form SHOULD be present.
	expectedHash := hashDevicePk(state.AuditSalt, devPkB64)
	if !strings.Contains(logOutput, expectedHash) {
		t.Fatalf("audit log missing expected devicePkHash %q:\n%s", expectedHash, logOutput)
	}
}

// TestAuditEmitContainsExpectedFields — the structured record has the
// fields a creator needs to detect anomalies (event, hashed device,
// configId, policy mode, claimed attestation, ttl).
func TestAuditEmitContainsExpectedFields(t *testing.T) {
	dir := t.TempDir()
	// Configure a strict policy so the rejected branch fires too.
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"$NPVT_CREDENTIAL$"}},
		"attestationPolicy": {"mode": "strict"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	srv := NewServer(state, logger)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	io.ReadAll(httpResp.Body)

	// One audit record should have been emitted (the strict-rejected one).
	logOutput := logBuf.String()
	for _, field := range []string{
		`"event":"issue.attestation_rejected"`,
		`"devicePkHash"`,
		`"configId"`,
		`"claimedPlatform":"NONE"`,
		`"tokenPresent":false`,
		`"policyMode":"strict"`,
	} {
		if !strings.Contains(logOutput, field) {
			t.Errorf("audit log missing expected field %s:\n%s", field, logOutput)
		}
	}
}

// TestAuditEmitNeverLogsAttestationToken — even when the client sends
// a real attestation token (in observe mode, a future change will pass real
// Play Integrity blobs), the token itself MUST NOT appear in the log.
// tokenPresent is the boolean; the token itself is server-side.
func TestAuditEmitNeverLogsAttestationToken(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"$NPVT_CREDENTIAL$"}},
		"attestationPolicy": {"mode": "observe"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	srv := NewServer(state, logger)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	const sensitiveToken = "sentinel-play-integrity-token-VALUE-do-NOT-log"

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = sensitiveToken
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	io.ReadAll(httpResp.Body)

	if strings.Contains(logBuf.String(), sensitiveToken) {
		t.Fatalf("attestation token leaked into audit log:\n%s", logBuf.String())
	}
	if strings.Contains(logBuf.String(), `"tokenPresent":true`) == false {
		t.Errorf("expected tokenPresent:true to indicate the token was non-empty")
	}
}
