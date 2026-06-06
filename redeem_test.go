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

// All redeem tests share one configId because their assertions don't
// depend on routing between multiple configs — they're about token
// lifecycle, envelope shape, persistence, and concurrency. The constant
// is defined in mint_share_link_test.go (same package) so this file
// just references testCID.

// TestRedeemRoundTrip is the happy path: a registered token + a
// recipient pubkey + a config in configs.json all line up and the
// endpoint returns a sealed V2 envelope addressed to the recipient.
func TestRedeemRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// configs.json: one entry the token will point at.
	writeConfigs(t, dir, []ConfigEntry{
		{
			ConfigID:           testCID,
			CredentialEncoding: credEncodingUuidV4,
			Config: json.RawMessage(`{
				"name": "alpha",
				"address": "vpn-a.example:443",
				"type": "V2RAY",
				"v2rayProfile": {
					"server": "vpn-a.example",
					"serverPort": "443",
					"password": "$NPVT_CREDENTIAL$"
				}
			}`),
		},
	})

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"

	// Pre-register a redemption token pointing at testCID.
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

	// Recipient: real P-256 keypair, send the compressed pubkey.
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

	// Response must be the raw envelope bytes — verify by running them
	// through the same envelope decoder a recipient would use.
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

	// The envelope's header configId MUST equal the token's configId.
	// This is the load-bearing 3.6g property: the recipient reads this
	// configId from the header, sends it to /v1/issue, and the server
	// routes via the SAME value.
	if dec.Header.ConfigID != testCID {
		t.Errorf("envelope header configId = %q, want token's configId %q",
			dec.Header.ConfigID, testCID)
	}

	// Token's RemainingRedemptions should now be 2.
	got := state.LookupRedemptionToken(tokenStr)
	if got == nil {
		t.Fatalf("token disappeared after redemption")
	}
	if got.RemainingRedemptions != 2 {
		t.Errorf("expected RemainingRedemptions=2 after one consume, got %d", got.RemainingRedemptions)
	}
}

// TestRedeemReusesConfigIDAcrossRedemptions confirms the property
// from RedemptionToken's kdoc: two recipients redeeming the same
// token get envelopes with the SAME configId, so a recipient holding
// two devices sees "this is the same logical config" via newest-wins
// reconciliation.
func TestRedeemReusesConfigIDAcrossRedemptions(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:           testCID,
		CredentialEncoding: credEncodingUuidV4,
		Config:             json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

// TestRedeemUnknownTokenReturns404 — the token doesn't exist.
func TestRedeemUnknownTokenReturns404(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

// TestRedeemExhaustedReturns410 — the token was registered but its
// remaining count is 0.
func TestRedeemExhaustedReturns410(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

// TestRedeemExpiredReturns410 — token has an expiresAt in the past.
func TestRedeemExpiredReturns410(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	state.AddRedemptionToken(RedemptionToken{
		Token:                "old",
		ConfigID:             testCID,
		RemainingRedemptions: 5,
		ExpiresAt:            "2025-01-01T00:00:00Z", // way in the past
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

// TestRedeemMalformedPubkeyReturns400 — junk in recipientPubkey is
// caught before the token is consumed.
func TestRedeemMalformedPubkeyReturns400(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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
	// Slot should NOT have been consumed.
	got := state.LookupRedemptionToken("good-token")
	if got.RemainingRedemptions != 5 {
		t.Errorf("malformed pubkey should not have consumed a slot: remaining = %d, want 5",
			got.RemainingRedemptions)
	}
}

// TestRedeemMissingPublicIssuerURL — operator forgot to set
// -public-issuer-url. Should return 500 with a clear server_error.
func TestRedeemMissingPublicIssuerURL(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	// Deliberately DON'T set state.PublicIssuerURL.
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

// TestRedeemPersistsAcrossRestart — decrement is durable: write to
// disk, reopen state, count reflects the consumed slot.
func TestRedeemPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

	// Reopen state from disk.
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

	// File on disk has 0o600 perms (Unix).
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

// TestRedeemConcurrentRedemptionsCannotOverdraw — N goroutines hammering
// a token with M=1 redemption slot. Exactly one should succeed; the
// others should all return 410 token_exhausted.
//
// Run this test with `go test -race` to catch any races in the
// consume path.
func TestRedeemConcurrentRedemptionsCannotOverdraw(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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
	// And the on-disk state reflects RemainingRedemptions=0.
	if got := state.LookupRedemptionToken("race-tok").RemainingRedemptions; got != 0 {
		t.Errorf("RemainingRedemptions = %d, want 0", got)
	}
}

// TestRedeemHotReloadsTokensWhenFileChanges — the load-bearing 3.6g-3
// property. Server starts with an empty redemption-tokens.json (or no
// file). A separate process (here, simulated by editing the file on
// disk) adds a token. The next /v1/redeem call MUST honor the new
// token without a server restart. Without hot-reload, recipients see
// 404 until systemctl restart — a real operational papercut.
func TestRedeemHotReloadsTokensWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:           testCID,
		CredentialEncoding: credEncodingUuidV4,
		Config:             json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// First attempt: no token registered. Should 404.
	httpResp := postRedeemRaw(t, ts, RedeemRequest{
		V:               1,
		Token:           "hotload-tok",
		RecipientPubkey: b64url.EncodeToString(freshRecipientPubkey(t)),
	})
	if httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("first attempt: expected 404 before token registered, got %d", httpResp.StatusCode)
	}
	httpResp.Body.Close()

	// Simulate `creator-server mint-share-link` writing a new token
	// to disk. The running server didn't AddRedemptionToken in-
	// process; it has to pick this up via mtime poll.
	//
	// Sleep just enough that the new file's mtime is reliably after
	// the existing file's. Most filesystems have second-resolution
	// mtimes; tests on Windows/Linux both need ~1.1s to guarantee a
	// strictly-later mtime even on FAT-like coarse-resolution stamps.
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

	// Second attempt: same token, no restart. Should NOW succeed
	// because the handler reloads on mtime change.
	envBytes := postRedeem(t, ts, "hotload-tok", freshRecipientPubkey(t))
	if len(envBytes) == 0 {
		t.Fatalf("expected envelope bytes after hot-reload, got empty body")
	}
}

// TestRedeemHotReloadRespectsRemovedFile — operator does `mv
// redemption-tokens.json tokens.bak` to disable redemption. Next
// /v1/redeem should 404 (the in-memory token from previous load is
// dropped to match the on-disk state).
func TestRedeemHotReloadRespectsRemovedFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:           testCID,
		CredentialEncoding: credEncodingUuidV4,
		Config:             json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

	// First call succeeds.
	postRedeem(t, ts, "will-be-removed", freshRecipientPubkey(t))

	// Operator removes the file out-of-band.
	if err := os.Remove(filepath.Join(dir, "redemption-tokens.json")); err != nil {
		t.Fatalf("remove tokens file: %v", err)
	}

	// Next /v1/redeem hot-reloads (file missing → empty map), the
	// token disappears, request 404s.
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

// TestRedeemRateLimitedByIP — many requests from the same IP get
// rate-limited.
func TestRedeemRateLimitedByIP(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
	}})
	state, _ := NewStateWithDir(dir)
	state.PublicIssuerURL = "https://issuer.example/v1/issue"

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// Hammer the endpoint with bad-pubkey requests (which fail fast
	// without consuming any token slot) past the per-IP limit.
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

// invalidCompressedPubkey returns a 33-byte value that is the right
// LENGTH for a SEC 1 compressed P-256 point but is NOT on the curve
// (x = 2^256-1 exceeds the field prime, so UnmarshalCompressed rejects
// it). Used to prove the pre-mint validity gate fires before the
// expensive envelope mint: a well-formed-length-but-off-curve pubkey
// only fails *inside* mintIssuerEnvelope, so if the handler returns the
// token-status error instead of bad_pubkey, the mint was never reached.
func invalidCompressedPubkey() []byte {
	b := make([]byte, envelopeP256CompLen)
	b[0] = 0x02
	for i := 1; i < len(b); i++ {
		b[i] = 0xFF
	}
	return b
}

// TestRedeemExhaustedSkipsMint confirms an exhausted token is rejected
// BEFORE mintIssuerEnvelope runs. With an off-curve recipient pubkey,
// the only way to get token_exhausted (rather than bad_pubkey from the
// failed mint) is for the exhaustion check to short-circuit ahead of
// the mint — the CPU-amplification fix.
func TestRedeemExhaustedSkipsMint(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

// TestRedeemExpiredSkipsMint is the expiry counterpart of
// TestRedeemExhaustedSkipsMint.
func TestRedeemExpiredSkipsMint(t *testing.T) {
	dir := t.TempDir()
	writeConfigs(t, dir, []ConfigEntry{{
		ConfigID:    testCID,
		Config:      json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}}`),
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

// TestClientIPXForwardedForTrust pins the rate-limit-key derivation:
// X-Forwarded-For must only be believed when the immediate peer is a
// declared trusted proxy. A direct client (no trusted proxies, or a
// peer outside the trusted set) cannot spoof its key via the header.
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

// ──────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────

// freshRecipientPubkey returns a P-256 compressed pubkey suitable for
// passing to a redemption request. Caller owns the key (the private
// key is dropped; we only need the public side for this layer).
func freshRecipientPubkey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pubkey: %v", err)
	}
	pub := priv.PublicKey().Bytes() // 65-byte uncompressed
	compressed, err := compressUncompressedP256(pub)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	return compressed
}

// postRedeem sends a redemption request and asserts success. Returns
// the raw envelope bytes from the response. Fails the test on any
// non-200.
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

// postRedeemRaw sends a redemption request and returns the raw
// response without asserting status code. Caller owns the response
// body lifecycle.
func postRedeemRaw(t *testing.T, ts *httptest.Server, req RedeemRequest) *http.Response {
	t.Helper()
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/redeem: %v", err)
	}
	return httpResp
}
