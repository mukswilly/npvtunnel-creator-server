package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIssueRoundTrip exercises the full POST /v1/issue happy-path:
//
//  1. Generate a fresh device P-256 keypair.
//  2. Sign a canonical IssueRequest with the device key.
//  3. POST it to a test server.
//  4. Verify the response's receiptSig against the server's creator pubkey.
//
// This exercises the /v1/issue wire-protocol foundation — proves the
// signature canonicalization matches the documented wire format.
func TestIssueRoundTrip(t *testing.T) {
	srv, state, ts := newTestServer(t)
	defer ts.Close()
	_ = srv

	// Device side: generate a signing key and a (config_fp, request_nonce).
	devPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen device key: %v", err)
	}
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	configID := b64url.EncodeToString(randomBytes(t, 32))
	requestNonce := b64url.EncodeToString(randomBytes(t, 16))

	req := IssueRequest{
		V:        1,
		DevicePk: devPkB64,
		Attestation: AttestationBlob{
			Platform: "NONE",
			Token:    "",
			Nonce:    b64url.EncodeToString(randomBytes(t, 16)),
		},
		ConfigID:     configID,
		RequestNonce: requestNonce,
	}
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	// Send.
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/issue: %v", err)
	}
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", httpResp.StatusCode, respBytes)
	}

	var resp IssueResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("parse response: %v (body=%s)", err, respBytes)
	}

	// Validate response shape — current wire format.
	if resp.ConfigB64 == "" || resp.ExpiresAt == "" || resp.ReceiptSig == "" {
		t.Fatalf("response missing required fields: %+v", resp)
	}

	// Verify the receipt signature against the creator pubkey. The
	// signing input covers ConfigB64 verbatim, so the recipient verifies
	// the bytes-on-the-wire before decoding the inner ConfigBody.
	creatorPub := &state.CreatorSigningKey.PublicKey
	receiptInput := issueReceiptSigningInput(req.DevicePk, req.RequestNonce, &resp)
	receiptSig, err := b64url.DecodeString(resp.ReceiptSig)
	if err != nil {
		t.Fatalf("decode receipt sig: %v", err)
	}
	if !verifyP1363Signature(creatorPub, receiptInput, receiptSig) {
		t.Fatalf("receipt signature did not verify")
	}

	// And the embedded ConfigBody parses as JSON. The stub path produces
	// a minimal V2RAY-typed body; this asserts the wire path is intact
	// end-to-end without depending on a configs.json.
	configBytes, err := b64url.DecodeString(resp.ConfigB64)
	if err != nil {
		t.Fatalf("decode configB64: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatalf("inner config not valid JSON: %v (bytes=%s)", err, configBytes)
	}
	if cfg["type"] != "V2RAY" && cfg["type"] != "SSH" {
		t.Fatalf("inner config.type = %v, want V2RAY or SSH", cfg["type"])
	}
}

// TestIssueRejectsBadSignature confirms that tampering with any field after
// signing invalidates the signature.
func TestIssueRejectsBadSignature(t *testing.T) {
	_, _, ts := newTestServer(t)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	req := IssueRequest{
		V:        1,
		DevicePk: devPkB64,
		Attestation: AttestationBlob{
			Platform: "NONE", Token: "", Nonce: b64url.EncodeToString(randomBytes(t, 16)),
		},
		ConfigID:     b64url.EncodeToString(randomBytes(t, 32)),
		RequestNonce: b64url.EncodeToString(randomBytes(t, 16)),
	}
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))
	// Tamper after signing.
	req.ConfigID = b64url.EncodeToString(randomBytes(t, 32))

	body, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/issue: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}
	respBytes, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBytes), "bad_signature") {
		t.Fatalf("expected bad_signature error code, got: %s", respBytes)
	}
}

// TestIssueRejectsMissingField confirms that absent required fields yield 400.
func TestIssueRejectsMissingField(t *testing.T) {
	_, _, ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/issue", "application/json",
		strings.NewReader(`{"v":1,"devicePk":"AAAA"}`))
	if err != nil {
		t.Fatalf("POST /v1/issue: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// TestCreatorPubKeyEndpoint exposes the server's signing pubkey.
func TestCreatorPubKeyEndpoint(t *testing.T) {
	_, state, ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/creator-pubkey")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		CreatorPubkey string `json:"creatorPubkey"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.CreatorPubkey != state.CreatorPubKeyCompressedB64() {
		t.Fatalf("pubkey mismatch: %s vs %s", out.CreatorPubkey, state.CreatorPubKeyCompressedB64())
	}
}

// ──────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*Server, *State, *httptest.Server) {
	t.Helper()
	state := NewState()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(state, logger)
	return srv, state, httptest.NewServer(srv.Router())
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func compressP256ToB64(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	xBytes := pub.X.Bytes()
	out := make([]byte, 33)
	if pub.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[33-len(xBytes):], xBytes)
	return b64url.EncodeToString(out)
}

func signWithP256(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	hash := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return b64url.EncodeToString(sig)
}
