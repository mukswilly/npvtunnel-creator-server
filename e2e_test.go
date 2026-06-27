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

// TestEndToEndRedeemThenIssue exercises the full flow against one server: redeem a token for an
// envelope, read the configId from the envelope header, then issue against that configId and
// confirm the issued config carries the registered config verbatim. This pins that the header's
// configId matches the registered configs key that /v1/issue routes on.
func TestEndToEndRedeemThenIssue(t *testing.T) {
	dir := t.TempDir()

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

	devPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen device key: %v", err)
	}
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	recipientPubCompressed := freshRecipientPubkey(t)

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

	dec, err := decodeEnvelopeWire(envelopeBytes)
	if err != nil {
		t.Fatalf("decode envelope wire: %v", err)
	}
	recipientConfigID := dec.Header.ConfigID

	if recipientConfigID != testCID {
		t.Fatalf("recipient extracted configId %q; want testCID %q (envelope-header value should match the registered configs.json key)",
			recipientConfigID, testCID)
	}

	issueReq := IssueRequest{
		V:        1,
		DevicePk: devPkB64,
		// "NONE" attestation: no hardware attestation is required for issuance.
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
