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

// TestCreatorKeyPersistsAcrossStateReopen confirms the pubkey is stable
// across NewStateWithDir calls in the same directory. If this breaks, every
// recipient with a pinned creator pubkey breaks on each deploy.
func TestCreatorKeyPersistsAcrossStateReopen(t *testing.T) {
	dir := t.TempDir()

	first, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("first NewStateWithDir: %v", err)
	}
	firstPub := first.CreatorPubKeyCompressedB64()

	// Verify the file actually got written.
	keyPath := filepath.Join(dir, "creator-key.pem")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected creator-key.pem at %s: %v", keyPath, err)
	}

	// Re-open the same directory — must load the existing key, not generate
	// a new one.
	second, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("second NewStateWithDir: %v", err)
	}
	if second.CreatorPubKeyCompressedB64() != firstPub {
		t.Fatalf("pubkey changed across reopen: %s -> %s", firstPub, second.CreatorPubKeyCompressedB64())
	}
}

// TestCreatorKeyHasRestrictivePermissions verifies the private key file is
// not world-readable. On Windows the perms model differs but the WriteFile
// 0600 still keeps the file out of "everyone" ACLs.
func TestCreatorKeyHasRestrictivePermissions(t *testing.T) {
	if isWindows() {
		t.Skip("Unix perm bits don't apply on Windows; ACL check is out of scope")
	}
	dir := t.TempDir()
	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "creator-key.pem"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	const wantMax os.FileMode = 0o600
	if info.Mode().Perm()&^wantMax != 0 {
		t.Fatalf("creator key perms = %o, want subset of %o", info.Mode().Perm(), wantMax)
	}
}

// TestCreatorKeyRejectsCorruptFile fails fast on a corrupt PEM rather than
// silently regenerating (which would break recipients without warning).
func TestCreatorKeyRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creator-key.pem"), []byte("not a PEM file"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected error on corrupt key file, got nil")
	}
}

// TestConfigsFileMissingFallsBackToStub confirms that without a configs.json,
// /v1/issue still returns a valid signed response (stub ConfigBody) — the
// wire-protocol harness should not depend on a config registry being present.
func TestConfigsFileMissingFallsBackToStub(t *testing.T) {
	dir := t.TempDir()
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if state.HasConfigRegistry() {
		t.Fatalf("expected HasConfigRegistry() == false without configs.json")
	}

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	respBytes := mustIssueRaw(t, ts, "anything")
	cfg := decodeIssueResponseConfig(t, respBytes)
	if cfg["name"] != "stub" {
		t.Fatalf("expected stub config, got name=%v", cfg["name"])
	}
}

// TestConfigsFileRoutesByConfigID confirms that when a config registry is
// loaded, /v1/issue returns the registered entry's Config — and that two
// entries route to two different configs.
func TestConfigsFileRoutesByConfigID(t *testing.T) {
	dir := t.TempDir()

	configs := []ConfigEntry{
		{
			ConfigID: "AAAAAAAAAAAAAAAAAAAAAA",
			Config: json.RawMessage(`{
				"name": "alpha",
				"address": "vpn-a.example:443",
				"type": "V2RAY",
				"v2rayProfile": {
					"server": "vpn-a.example",
					"serverPort": "443",
					"password": "a1b2c3d4-0000-4000-8000-000000000001",
					"sni": "a.example",
					"fingerPrint": "chrome"
				}
			}`),
		},
		{
			ConfigID: "EBAQEBAQEBAQEBAQEBAQEA",
			Config: json.RawMessage(`{
				"name": "bravo",
				"address": "vpn-b.example:8443",
				"type": "SSH",
				"sshConfig": {
					"sshHost": "vpn-b.example",
					"sshPort": 8443,
					"sshUsername": "user",
					"sshPassword": "static-ssh-password-xyz"
				}
			}`),
		},
	}
	writeConfigs(t, dir, configs)

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !state.HasConfigRegistry() {
		t.Fatalf("expected HasConfigRegistry() == true after configs.json")
	}

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// fp-A: V2RAY routing.
	cfgA := decodeIssueResponseConfig(t, mustIssueRaw(t, ts, "AAAAAAAAAAAAAAAAAAAAAA"))
	if cfgA["type"] != "V2RAY" {
		t.Fatalf("fp-A type = %v, want V2RAY", cfgA["type"])
	}
	if cfgA["address"] != "vpn-a.example:443" {
		t.Fatalf("fp-A address = %v", cfgA["address"])
	}
	profileA, _ := cfgA["v2rayProfile"].(map[string]any)
	if profileA["sni"] != "a.example" {
		t.Fatalf("fp-A sni = %v", profileA["sni"])
	}
	if profileA["password"] != "a1b2c3d4-0000-4000-8000-000000000001" {
		t.Fatalf("fp-A credential not returned verbatim, got %v", profileA["password"])
	}

	// fp-B: SSH routing — completely different protocol, same code path.
	// This is the test that proves the protocol-agnostic design unlocked the "every protocol
	// just works" property.
	cfgB := decodeIssueResponseConfig(t, mustIssueRaw(t, ts, "EBAQEBAQEBAQEBAQEBAQEA"))
	if cfgB["type"] != "SSH" {
		t.Fatalf("fp-B type = %v, want SSH", cfgB["type"])
	}
	sshB, _ := cfgB["sshConfig"].(map[string]any)
	if sshB["sshHost"] != "vpn-b.example" {
		t.Fatalf("fp-B sshHost = %v", sshB["sshHost"])
	}
	if sshB["sshPassword"] != "static-ssh-password-xyz" {
		t.Fatalf("fp-B credential not returned verbatim, got %v", sshB["sshPassword"])
	}
}

// TestConfigsFileUnknownFpReturns404 confirms that a recipient asking for
// a fp the issuer doesn't know about gets a clean error rather than the
// stub credential.
func TestConfigsFileUnknownFpReturns404(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{
		{
			ConfigID: "AAAAAAAAAAAAAAAAAAAAAA",
			Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
		},
	})
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// Sign a request for fp-Unknown.
	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "fp-Unknown")
	body, _ := json.Marshal(req)

	httpResp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", httpResp.StatusCode)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	if !strings.Contains(string(respBytes), "config_not_found") {
		t.Fatalf("expected config_not_found error, got: %s", respBytes)
	}
}

// TestConfigsFileRejectsDuplicateFp guards against an operator footgun:
// two entries with the same fp would cause non-deterministic routing.
func TestConfigsFileRejectsDuplicateFp(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{
		{ConfigID: "AAAAAAAAAAAAAAAAAAAAAA", Config: json.RawMessage(`{"type":"V2RAY"}`)},
		{ConfigID: "AAAAAAAAAAAAAAAAAAAAAA", Config: json.RawMessage(`{"type":"V2RAY"}`)},
	})
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected error on duplicate configId, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-related error, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────

func newTestServerWithState(t *testing.T, state *State) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(state, logger)
	return httptest.NewServer(srv.Router())
}

func writeConfigs(t *testing.T, dir string, entries []ConfigEntry) {
	t.Helper()
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal configs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "configs.json"), data, 0o600); err != nil {
		t.Fatalf("write configs: %v", err)
	}
}

// buildSignedIssueRequest creates a properly-signed IssueRequest for the
// given configId. Used across all /v1/issue test paths.
func buildSignedIssueRequest(t *testing.T, devPriv *ecdsa.PrivateKey, configID string) IssueRequest {
	t.Helper()
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)
	req := IssueRequest{
		V:        1,
		DevicePk: devPkB64,
		Attestation: AttestationBlob{
			Platform: "NONE", Token: "", Nonce: b64url.EncodeToString(randomBytes(t, 16)),
		},
		ConfigID:     configID,
		RequestNonce: b64url.EncodeToString(randomBytes(t, 16)),
	}
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))
	return req
}

// mustIssueRaw POSTs a signed request for configId and returns the raw
// response body. Fails on non-200.
func mustIssueRaw(t *testing.T, ts *httptest.Server, configID string) []byte {
	t.Helper()
	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, configID)
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", httpResp.StatusCode, respBytes)
	}
	return respBytes
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}
