package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestEndToEndRedeemThenIssue is the load-bearing integration test
// that bridges /v1/redeem and /v1/issue against a single running
// server.
//
// What it proves:
//
//  1. A recipient redeems a share-link token, gets back a sealed
//     envelope addressed to its device.
//  2. The recipient extracts the configId from the envelope HEADER
//     (the configId comes from the envelope header, not from SHA-256 of bytes).
//  3. The recipient signs an IssueRequest carrying that configId and
//     POSTs to /v1/issue.
//  4. /v1/issue returns 200 with a usable ConfigBody.
//
// In an earlier broken design, step (3) sent a different configId per recipient
// (the SHA-256 hash differed for every redemption), so step (4) 404'd
// with config_not_found. The unit tests didn't catch this because they
// stopped at step (2). This integration test goes the full distance.
//
// If this test ever regresses, the share-link distribution flow is
// broken end-to-end — recipients can redeem but can't connect.
func TestEndToEndRedeemThenIssue(t *testing.T) {
	dir := t.TempDir()

	// Server setup: one configs.json entry, one redemption token.
	// Both use the same testCID (the routing key).
	writeConfigs(t, dir, []ConfigEntry{{
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
	}})
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	state.PublicIssuerURL = "https://issuer.example/v1/issue"
	const tokenStr = "e2e-tok"
	state.AddRedemptionToken(RedemptionToken{
		Token:                tokenStr,
		ConfigID:             testCID,
		RemainingRedemptions: 1,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	})
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	// ─── Recipient side ───────────────────────────────────────────

	// Recipient's signing key (a hardware-backed device key in
	// production; the test uses a software key).
	devPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen device key: %v", err)
	}
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	// The recipient's ECDH key for envelope unsealing. In production
	// this is a separate hardware-backed device key; for the
	// integration we just need the pubkey to address the envelope to.
	recipientPubCompressed := freshRecipientPubkey(t)

	// ─── Step 1+2: redeem ─────────────────────────────────────────

	redeemReq := RedeemRequest{
		V:               1,
		Token:           tokenStr,
		RecipientPubkey: b64url.EncodeToString(recipientPubCompressed),
	}
	redeemBody, _ := json.Marshal(redeemReq)
	redeemResp, err := http.Post(ts.URL+"/v1/redeem", "application/json", bytes.NewReader(redeemBody))
	if err != nil {
		t.Fatalf("POST /v1/redeem: %v", err)
	}
	envelopeBytes, _ := io.ReadAll(redeemResp.Body)
	redeemResp.Body.Close()
	if redeemResp.StatusCode != http.StatusOK {
		t.Fatalf("redeem status %d: %s", redeemResp.StatusCode, envelopeBytes)
	}

	// Recipient parses the envelope header. The key step that
	// distinguishes the current design from the previous broken one: the
	// configId comes from envelope.header.ConfigID, NOT from
	// SHA-256(envelopeBytes).
	dec, err := decodeEnvelopeWire(envelopeBytes)
	if err != nil {
		t.Fatalf("decode envelope wire: %v", err)
	}
	recipientConfigID := dec.Header.ConfigID

	// Sanity: the configId the recipient extracted MUST equal the
	// configs.json entry's configId. This is the property that makes
	// /v1/issue routing work; if a future refactor breaks it the
	// recipient's next /v1/issue 404s.
	if recipientConfigID != testCID {
		t.Fatalf("recipient extracted configId %q; want testCID %q (envelope-header value should match the registered configs.json key)",
			recipientConfigID, testCID)
	}

	// ─── Step 3+4: issue ──────────────────────────────────────────

	issueReq := IssueRequest{
		V:        1,
		DevicePk: devPkB64,
		Attestation: AttestationBlob{
			Platform: "NONE", Token: "", Nonce: b64url.EncodeToString(randomBytes(t, 16)),
		},
		ConfigID:     recipientConfigID,
		RequestNonce: b64url.EncodeToString(randomBytes(t, 16)),
	}
	issueReq.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&issueReq))

	issueBody, _ := json.Marshal(issueReq)
	issueResp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(issueBody))
	if err != nil {
		t.Fatalf("POST /v1/issue: %v", err)
	}
	defer issueResp.Body.Close()
	issueRespBytes, _ := io.ReadAll(issueResp.Body)
	if issueResp.StatusCode != http.StatusOK {
		t.Fatalf("issue status %d: %s\n\n"+
			"This is the load-bearing end-to-end assertion: redemption + "+
			"issue must work end-to-end against one server. A 404 here "+
			"means the configId the recipient extracted from the "+
			"envelope header doesn't match the configs.json entry — "+
			"check that mintIssuerEnvelope's header.ConfigID equals "+
			"the operator-supplied configId and that /v1/issue routes "+
			"on that exact value.",
			issueResp.StatusCode, issueRespBytes)
	}

	// And the issued ConfigBody decodes + carries the operator's static
	// config verbatim. (Here we're confirming the *path through
	// /v1/redeem* still arrives at the routed configs.json entry.)
	var resp IssueResponse
	if err := json.Unmarshal(issueRespBytes, &resp); err != nil {
		t.Fatalf("parse issue response: %v", err)
	}
	configBytes, err := b64url.DecodeString(resp.ConfigB64)
	if err != nil {
		t.Fatalf("decode configB64: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatalf("parse inner config: %v", err)
	}
	profile, _ := cfg["v2rayProfile"].(map[string]any)
	if profile["password"] != "a1b2c3d4-0000-4000-8000-000000000001" {
		t.Fatalf("issued config did not carry the static config verbatim, got: %v", profile["password"])
	}
}
