package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRedeemRoundTrip verifies a valid token yields a 200 with an octet-stream envelope whose
// header carries the token's configId, and that one redemption decrements the remaining count.
func TestRedeemRoundTrip(t *testing.T) {
	dir := t.TempDir()

	writeConfigs(t, dir, []ConfigEntry{
		{
			ConfigID: testCID,
			Config: json.RawMessage(`{
				"name": "alpha",
				"address": "vpn-a.example:443",
				"type": "V2RAY",
				"v2rayProfile": {
					"server": "vpn-a.example",
					"serverPort": "443",
					"password": "a1b2c3d4-0000-4000-8000-000000000001"
				}
			}`),
		},
	})

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"

	const tokenStr = "TEST-token-aaaaaaaaaaaaaaaaaaaa"
	if err := state.AddRedemptionToken(RedemptionToken{
		Token:                tokenStr,
		ConfigID:             testCID,
		RemainingRedemptions: 3,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
		Label:                "test",
	}); err != nil {
		t.Fatalf("add token: %v", err)
	}

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	recipientPubCompressed := freshRecipientPubkey(t)

	req := RedeemRequest{
		V:               1,
		Token:           tokenStr,
		RecipientPubkey: b64url.EncodeToString(recipientPubCompressed),
	}
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer httpResp.Body.Close()
	envelopeBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", httpResp.StatusCode, envelopeBytes)
	}

	if got := httpResp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	dec, err := decodeEnvelopeWire(envelopeBytes)
	if err != nil {
		t.Fatalf("decode envelope wire: %v", err)
	}
	if len(dec.Header.Recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(dec.Header.Recipients))
	}

	if dec.Header.ConfigID != testCID {
		t.Errorf("envelope header configId = %q, want token's configId %q",
			dec.Header.ConfigID, testCID)
	}

	got := state.LookupRedemptionToken(tokenStr)
	if got == nil {
		t.Fatalf("token disappeared after redemption")
	}
	if got.RemainingRedemptions != 2 {
		t.Errorf("expected RemainingRedemptions=2 after one consume, got %d", got.RemainingRedemptions)
	}
}

// TestRedeemReusesConfigIDAcrossRedemptions verifies repeated redemptions of one token all carry the same configId.
func TestRedeemReusesConfigIDAcrossRedemptions(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"

	const tokenStr = "two-redemptions-token"
	state.AddRedemptionToken(RedemptionToken{
		Token:                tokenStr,
		ConfigID:             testCID,
		RemainingRedemptions: 2,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	configIDs := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		envBytes := postRedeem(t, ts, tokenStr, freshRecipientPubkey(t))
		dec, err := decodeEnvelopeWire(envBytes)
		if err != nil {
			t.Fatalf("decode envelope %d: %v", i, err)
		}
		configIDs = append(configIDs, dec.Header.ConfigID)
	}
	if configIDs[0] != configIDs[1] {
		t.Fatalf("configId not stable across redemptions: %q vs %q", configIDs[0], configIDs[1])
	}
}

// TestRedeemUnknownTokenReturns404 verifies an unregistered token returns 404 with a token_not_found code.
func TestRedeemUnknownTokenReturns404(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "definitely-not-registered",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", httpResp.StatusCode)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	if !strings.Contains(string(respBytes), "token_not_found") {
		t.Fatalf("expected token_not_found code, got: %s", respBytes)
	}
}

// TestRedeemExhaustedReturns410 verifies a token with no remaining redemptions returns 410 with a token_exhausted code.
func TestRedeemExhaustedReturns410(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "spent",
		ConfigID:             testCID,
		RemainingRedemptions: 0,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "spent",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", httpResp.StatusCode)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	if !strings.Contains(string(respBytes), "token_exhausted") {
		t.Fatalf("expected token_exhausted, got: %s", respBytes)
	}
}

// TestRedeemExpiredReturns410 verifies a token past its expiry returns 410 with a token_expired code.
func TestRedeemExpiredReturns410(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "old",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		ExpiresAt:            "2025-01-01T00:00:00Z",
		CreatedAt:            "2024-01-01T00:00:00Z",
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "old",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", httpResp.StatusCode)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	if !strings.Contains(string(respBytes), "token_expired") {
		t.Fatalf("expected token_expired, got: %s", respBytes)
	}
}

// TestRedeemMalformedPubkeyReturns400 verifies a non-base64 recipient pubkey returns 400 and does not consume a redemption.
func TestRedeemMalformedPubkeyReturns400(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "good-token",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "good-token",
		RecipientPubkey: "not-base64!!!",
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", httpResp.StatusCode)
	}

	got := state.LookupRedemptionToken("good-token")
	if got.RemainingRedemptions != 5 {
		t.Errorf("malformed pubkey should not have consumed a slot: remaining = %d, want 5",
			got.RemainingRedemptions)
	}
}

// TestRedeemMissingPublicIssuerURL verifies redemption fails with 500 server_error when the issuer URL is unconfigured.
func TestRedeemMissingPublicIssuerURL(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	// PublicIssuerURL deliberately left unset.
	state.AddRedemptionToken(RedemptionToken{
		Token:                "tok",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "tok",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", httpResp.StatusCode)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	if !strings.Contains(string(respBytes), "server_error") {
		t.Fatalf("expected server_error code, got: %s", respBytes)
	}
}

// TestRedeemPersistsAcrossRestart verifies redemption counts survive reopening state from disk, and that the tokens file keeps owner-only permissions.
func TestRedeemPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "persist-tok",
		ConfigID:             testCID,
		RemainingRedemptions: 10,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	postRedeem(t, ts, "persist-tok", freshRecipientPubkey(t))
	postRedeem(t, ts, "persist-tok", freshRecipientPubkey(t))
	ts.Close()

	reopened, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := reopened.LookupRedemptionToken("persist-tok")
	if got == nil {
		t.Fatalf("token didn't persist")
	}
	if got.RemainingRedemptions != 8 {
		t.Errorf("RemainingRedemptions = %d, want 8 after 2 consumes + restart", got.RemainingRedemptions)
	}

	// POSIX permission bits are not meaningful on Windows, so check them only elsewhere.
	if !isWindows() {
		info, err := os.Stat(filepath.Join(dir, "redemption-tokens.json"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm()&^0o600 != 0 {
			t.Errorf("perms = %o, want subset of 0600", info.Mode().Perm())
		}
	}
}

// TestRedeemConcurrentRedemptionsCannotOverdraw verifies that with one remaining redemption and many concurrent requests, exactly one succeeds and the count lands at zero.
func TestRedeemConcurrentRedemptionsCannotOverdraw(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "race-tok",
		ConfigID:             testCID,
		RemainingRedemptions: 1,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	const concurrency = 20
	successes := make(chan int, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			httpResp := postRedeemRaw(t, ts, RedeemRequest{
				V:               1,
				Token:           "race-tok",
				RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
			})
			defer httpResp.Body.Close()
			io.Copy(io.Discard, httpResp.Body)
			successes <- httpResp.StatusCode
		}()
	}
	wg.Wait()
	close(successes)

	var ok int
	for sc := range successes {
		if sc == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("with RemainingRedemptions=1 and concurrency=%d, exactly 1 should succeed; got %d", concurrency, ok)
	}

	if got := state.LookupRedemptionToken("race-tok").RemainingRedemptions; got != 0 {
		t.Errorf("RemainingRedemptions = %d, want 0", got)
	}
}

// TestRedeemHotReloadsTokensWhenFileChanges verifies a token written to the tokens file after startup becomes redeemable without a restart.
func TestRedeemHotReloadsTokensWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "hotload-tok",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	if httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("first attempt: expected 404 before token registered, got %d", httpResp.StatusCode)
	}
	httpResp.Body.Close()

	// Wait past the reload's mtime granularity so the rewritten file is seen as changed.
	time.Sleep(1100 * time.Millisecond)
	tokens := []RedemptionToken{{
		Token:                "hotload-tok",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}}
	tokensJSON, _ := json.Marshal(tokens)
	if err := os.WriteFile(filepath.Join(dir, "redemption-tokens.json"), tokensJSON, 0o600); err != nil {
		t.Fatalf("write tokens file: %v", err)
	}

	envBytes := postRedeem(t, ts, "hotload-tok", freshRecipientPubkey(t))
	if len(envBytes) == 0 {
		t.Fatalf("expected envelope bytes after hot-reload, got empty body")
	}
}

// TestRedeemHotReloadRespectsRemovedFile verifies removing the tokens file drops its tokens, so a previously valid token then returns 404.
func TestRedeemHotReloadRespectsRemovedFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "will-be-removed",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	postRedeem(t, ts, "will-be-removed", freshRecipientPubkey(t))

	if err := os.Remove(filepath.Join(dir, "redemption-tokens.json")); err != nil {
		t.Fatalf("remove tokens file: %v", err)
	}

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "will-be-removed",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after file removed, got %d", httpResp.StatusCode)
	}
}

// TestRedeemRateLimitedByIP verifies a single IP exceeding the per-hour cap gets a 429 with a Retry-After header.
func TestRedeemRateLimitedByIP(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	got429 := false
	for i := 0; i < redeemMaxPerIPPerHour+5; i++ {
		httpResp := postRedeemRaw(t, ts, RedeemRequest{
			V:               1,
			Token:           "nonexistent",
			RecipientPubkey: "AAAA",
		})
		if httpResp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			retryAfter := httpResp.Header.Get("Retry-After")
			if retryAfter == "" {
				t.Errorf("429 response missing Retry-After header")
			}
			httpResp.Body.Close()
			break
		}
		httpResp.Body.Close()
	}
	if !got429 {
		t.Fatalf("expected to hit rate limit within %d requests", redeemMaxPerIPPerHour+5)
	}
}

// invalidCompressedPubkey returns a well-formed-length but off-curve compressed point: the
// prefix is valid but the coordinate decodes to no point on P-256, so any attempt to use it
// for minting must fail. Used to prove token-status checks happen before the pubkey is decoded.
func invalidCompressedPubkey() []byte {
	b := make([]byte, envelopeP256CompLen)
	b[0] = 0x02
	for i := 1; i < len(b); i++ {
		b[i] = 0xFF
	}
	return b
}

// TestRedeemExhaustedSkipsMint verifies an exhausted token returns 410 even with an off-curve
// pubkey, proving the exhaustion check short-circuits before the pubkey is ever decoded for minting.
func TestRedeemExhaustedSkipsMint(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "spent-skip",
		ConfigID:             testCID,
		RemainingRedemptions: 0,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "spent-skip",
		RecipientPubkey: b64url.EncodeToString(invalidCompressedPubkey()),
	})
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410 (mint must be skipped before the off-curve pubkey is ever decoded); body %s",
			httpResp.StatusCode, respBytes)
	}
	if !strings.Contains(string(respBytes), "token_exhausted") {
		t.Fatalf("expected token_exhausted (mint skipped), got: %s", respBytes)
	}
}

// TestRedeemExpiredSkipsMint verifies an expired token returns 410 even with an off-curve
// pubkey, proving the expiry check short-circuits before the pubkey is ever decoded for minting.
func TestRedeemExpiredSkipsMint(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID: testCID,
		Config:   json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"a1b2c3d4-0000-4000-8000-000000000001"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "old-skip",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		ExpiresAt:            "2025-01-01T00:00:00Z",
		CreatedAt:            "2024-01-01T00:00:00Z",
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "old-skip",
		RecipientPubkey: b64url.EncodeToString(invalidCompressedPubkey()),
	})
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410 (mint must be skipped for expired token); body %s",
			httpResp.StatusCode, respBytes)
	}
	if !strings.Contains(string(respBytes), "token_expired") {
		t.Fatalf("expected token_expired (mint skipped), got: %s", respBytes)
	}
}

// TestClientIPXForwardedForTrust verifies clientIP only honors X-Forwarded-For from a trusted
// proxy peer, walks the chain to the rightmost untrusted hop, and otherwise falls back to the
// direct peer address — so a spoofed header from an untrusted peer cannot forge the client IP.
func TestClientIPXForwardedForTrust(t *testing.T) {
	trusted, err := parseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		trusted    []*net.IPNet
		want       string
	}{
		{
			name:       "no trusted proxies: XFF ignored even from private peer",
			remoteAddr: "10.1.2.3:5555",
			xff:        "1.2.3.4",
			trusted:    nil,
			want:       "10.1.2.3",
		},
		{
			name:       "untrusted peer: XFF ignored (spoof attempt)",
			remoteAddr: "203.0.113.9:443",
			xff:        "1.2.3.4",
			trusted:    trusted,
			want:       "203.0.113.9",
		},
		{
			name:       "trusted peer: XFF honored",
			remoteAddr: "10.0.0.1:443",
			xff:        "1.2.3.4",
			trusted:    trusted,
			want:       "1.2.3.4",
		},
		{
			name:       "trusted peer, chain: rightmost untrusted hop wins",
			remoteAddr: "10.0.0.1:443",
			xff:        "1.2.3.4, 10.0.0.2",
			trusted:    trusted,
			want:       "1.2.3.4",
		},
		{
			name:       "trusted peer, no XFF: falls back to peer",
			remoteAddr: "10.0.0.1:443",
			xff:        "",
			trusted:    trusted,
			want:       "10.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/redeem", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r, tc.trusted); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// freshRecipientPubkey returns a freshly generated, valid 33-byte compressed P-256 recipient pubkey.
func freshRecipientPubkey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pubkey: %v", err)
	}
	pub := priv.PublicKey().Bytes()
	compressed, err := compressUncompressedP256(pub)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	return compressed
}

// postRedeem posts a redeem request and returns the envelope bytes, failing the test on any non-200.
func postRedeem(t *testing.T, ts *httptest.Server, token string, recipientPubkey []byte) []byte {
	t.Helper()
	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           token,
		RecipientPubkey: b64url.EncodeToString(recipientPubkey),
	})
	defer httpResp.Body.Close()
	envelopeBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("redeem status %d, body %s", httpResp.StatusCode, envelopeBytes)
	}
	return envelopeBytes
}

// postRedeemRaw posts a redeem request and returns the raw response without asserting status, for tests that inspect error codes.
func postRedeemRaw(t *testing.T, ts *httptest.Server, req RedeemRequest) *http.Response {
	t.Helper()
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/redeem: %v", err)
	}
	return httpResp
}
