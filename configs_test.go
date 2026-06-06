package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────
// configs.json validation
// ──────────────────────────────────────────────────────────────────

// TestConfigsFileLoadRejectsMissingConfig — registered entries must
// supply a Config template. Forgotten field gets caught at startup.
func TestConfigsFileLoadRejectsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA"
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on missing config")
	}
	if !strings.Contains(err.Error(), "missing required field config") {
		t.Fatalf("expected missing-config message, got: %v", err)
	}
}

// TestConfigsFileLoadRejectsUnknownCredentialEncoding — typos on the
// encoding name caught at startup rather than at every issuance.
func TestConfigsFileLoadRejectsUnknownCredentialEncoding(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"credentialEncoding": "uuid-v3",
		"config": {"type":"V2RAY"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on unknown credentialEncoding")
	}
	if !strings.Contains(err.Error(), "credentialEncoding") {
		t.Fatalf("expected credentialEncoding message, got: %v", err)
	}
}

// decodeIssueResponseConfig parses an /v1/issue response body and
// returns the decoded ConfigBody as a generic map. Shared helper for
// the tests that need to inspect the issued config.
func decodeIssueResponseConfig(t *testing.T, respBytes []byte) map[string]any {
	t.Helper()
	var resp IssueResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("parse response: %v (body=%s)", err, respBytes)
	}
	configBytes, err := b64url.DecodeString(resp.ConfigB64)
	if err != nil {
		t.Fatalf("decode configB64: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatalf("parse config json: %v (bytes=%s)", err, configBytes)
	}
	return cfg
}
