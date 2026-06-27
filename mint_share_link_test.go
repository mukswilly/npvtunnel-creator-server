package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCID = "AAAAAAAAAAAAAAAAAAAAAA"

// Minting a share link persists one token carrying the requested configId,
// redemption count, and label, with no expiry unless -expires-in is given.
func TestMintShareLinkHappyPath(t *testing.T) {
	dir := t.TempDir()

	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("init state: %v", err)
	}
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
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

// A configId with no registered config is rejected and persists no token.
func TestMintShareLinkRejectsUnknownConfigID(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewStateWithDir(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})

	const unregisteredCID = "____________________8w"
	rc := runMintShareLinkSubcommand([]string{
		"-state-dir", dir,
		"-config-id", unregisteredCID,
		"-redemption-url", "https://issuer.example/v1/redeem",
	})
	if rc == 0 {
		t.Fatalf("expected non-zero rc for unknown configId")
	}

	tokens := readTokensFromDisk(t, dir)
	if len(tokens) != 0 {
		t.Errorf("expected no tokens after failed mint, got %d", len(tokens))
	}
}

// A non-https redemption URL is rejected.
func TestMintShareLinkRequiresHttps(t *testing.T) {
	dir := t.TempDir()
	NewStateWithDir(dir)
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
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

// -expires-in populates the token's ExpiresAt.
func TestMintShareLinkExpiresInIsApplied(t *testing.T) {
	dir := t.TempDir()
	NewStateWithDir(dir)
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
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

// Revoking a token by value removes it from the persisted token list.
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

// Revoking a token that was never issued exits non-zero.
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

// readTokensFromDisk loads the persisted redemption tokens, treating a missing
// or empty file as an empty list.
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
