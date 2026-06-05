package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testCID is a stable 16-byte configId for tests that don't care about
// the specific bytes. base64url-no-pad of 16 0x00 bytes — passes the
// configs.json load-time validator (which requires exactly 16 bytes).
const testCID = "AAAAAAAAAAAAAAAAAAAAAA"

// TestMintShareLinkHappyPath — operator runs mint-share-link against
// a state-dir that has the named configId registered; subcommand
// produces a join link and persists the token.
func TestMintShareLinkHappyPath(t *testing.T) {
	dir := t.TempDir()
	// First touch creates state files (creator-key.pem etc).
	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("init state: %v", err)
	}
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		VpnProtocol: "xray-vless-reality",
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})

	rc := runMintShareLinkSubcommand([]string{
		"-state-dir", dir,
		"-config-id", testCID,
		"-redemption-url", "https://issuer.example/v1/redeem",
		"-redemptions", "50",
		"-label", "test-channel",
	})
	if rc != 0 {
		t.Fatalf("mint-share-link rc = %d, want 0", rc)
	}

	// redemption-tokens.json now has one entry pointing at testCID.
	tokens := readTokensFromDisk(t, dir)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token after mint, got %d", len(tokens))
	}
	if tokens[0].ConfigID != testCID {
		t.Errorf("ConfigID = %q, want %q", tokens[0].ConfigID, testCID)
	}
	if tokens[0].RemainingRedemptions != 50 {
		t.Errorf("RemainingRedemptions = %d, want 50", tokens[0].RemainingRedemptions)
	}
	if tokens[0].Label != "test-channel" {
		t.Errorf("Label = %q, want test-channel", tokens[0].Label)
	}
	if tokens[0].ExpiresAt != "" {
		t.Errorf("ExpiresAt = %q, want empty (no -expires-in)", tokens[0].ExpiresAt)
	}
}

// TestMintShareLinkRejectsUnknownConfigID — the load-bearing safety
// property: a typo in -config-id fails at mint time, not at first
// recipient redemption (which is the bug 3.6g fixes end-to-end).
func TestMintShareLinkRejectsUnknownConfigID(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		VpnProtocol: "x",
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})

	// Use a syntactically-valid-but-not-registered configId.
	const unregisteredCID = "____________________8w"
	rc := runMintShareLinkSubcommand([]string{
		"-state-dir", dir,
		"-config-id", unregisteredCID,
		"-redemption-url", "https://issuer.example/v1/redeem",
	})
	if rc == 0 {
		t.Fatalf("expected non-zero rc for unknown configId")
	}
	// And nothing should have been persisted.
	tokens := readTokensFromDisk(t, dir)
	if len(tokens) != 0 {
		t.Errorf("expected no tokens after failed mint, got %d", len(tokens))
	}
}

// TestMintShareLinkRequiresHttps — operator can't accidentally
// publish a join link pointing at http:// (or a custom scheme).
func TestMintShareLinkRequiresHttps(t *testing.T) {
	dir := t.TempDir()
	NewStateWithDir(dir)
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		VpnProtocol: "x",
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})

	rc := runMintShareLinkSubcommand([]string{
		"-state-dir", dir,
		"-config-id", testCID,
		"-redemption-url", "http://issuer.example/v1/redeem",
	})
	if rc == 0 {
		t.Fatalf("expected non-zero rc for non-https redemption-url")
	}
}

// TestMintShareLinkExpiresInIsApplied — when the operator passes
// -expires-in, the persisted token has a non-empty ExpiresAt.
func TestMintShareLinkExpiresInIsApplied(t *testing.T) {
	dir := t.TempDir()
	NewStateWithDir(dir)
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		VpnProtocol: "x",
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})

	rc := runMintShareLinkSubcommand([]string{
		"-state-dir", dir,
		"-config-id", testCID,
		"-redemption-url", "https://issuer.example/v1/redeem",
		"-expires-in", "1h",
	})
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	tokens := readTokensFromDisk(t, dir)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].ExpiresAt == "" {
		t.Errorf("ExpiresAt should be set when -expires-in is provided")
	}
}

// TestRevokeTokenRemovesEntry — operator action removes the named
// token from redemption-tokens.json so subsequent redemptions get
// 404. Existing per-recipient envelopes already minted under this
// token are unaffected (they live on recipient devices already).
func TestRevokeTokenRemovesEntry(t *testing.T) {
	dir := t.TempDir()
	state, _ := NewStateWithDir(dir)
	if err := state.AddRedemptionToken(RedemptionToken{
		Token:                "to-revoke",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		CreatedAt:            "2026-05-27T12:00:00Z",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	rc := runRevokeTokenSubcommand([]string{
		"-state-dir", dir,
		"-token", "to-revoke",
	})
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	tokens := readTokensFromDisk(t, dir)
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after revoke, got %d", len(tokens))
	}
}

// TestRevokeTokenUnknownTokenFails — operator typo gets a clear
// error instead of silently doing nothing.
func TestRevokeTokenUnknownTokenFails(t *testing.T) {
	dir := t.TempDir()
	NewStateWithDir(dir)
	rc := runRevokeTokenSubcommand([]string{
		"-state-dir", dir,
		"-token", "never-existed",
	})
	if rc == 0 {
		t.Fatalf("expected non-zero rc for unknown token")
	}
}

// ──────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────

func readTokensFromDisk(t *testing.T, dir string) []RedemptionToken {
	t.Helper()
	path := filepath.Join(dir, "redemption-tokens.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read tokens: %v", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil
	}
	var list []RedemptionToken
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("parse tokens: %v", err)
	}
	return list
}
