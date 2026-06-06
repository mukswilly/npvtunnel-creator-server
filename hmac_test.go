package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestVpnHmacKeyPersistsAcrossStateReopen confirms the HMAC key (like the
// creator signing key) survives a restart. The key is pre-shared with the
// VPN server; if it changed on restart, every active tunnel would die.
func TestVpnHmacKeyPersistsAcrossStateReopen(t *testing.T) {
	dir := t.TempDir()

	first, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	firstKey := append([]byte{}, first.VpnHmacKey...)

	keyPath := filepath.Join(dir, "vpn-hmac-key.bin")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected vpn-hmac-key.bin at %s: %v", keyPath, err)
	}
	if info.Size() != 32 {
		t.Fatalf("vpn-hmac-key.bin size = %d, want 32", info.Size())
	}

	second, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !bytes.Equal(firstKey, second.VpnHmacKey) {
		t.Fatalf("VpnHmacKey changed across reopen — would invalidate all VPN-server-side credentials")
	}
}

// TestVpnHmacKeyRejectsWrongSize fails loudly on corruption rather than
// silently regenerating (which would break every active tunnel).
func TestVpnHmacKeyRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vpn-hmac-key.bin"), make([]byte, 16), 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected error on wrong-size hmac key, got nil")
	}
}

// TestDeriveCredentialBytesIsDeterministic — same input always produces
// the same bytes, otherwise the VPN-server-side reverification would be
// impossible.
func TestDeriveCredentialBytesIsDeterministic(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	devicePk := "device-pubkey-base64"
	expiresAt := "2026-05-27T13:00:00Z"

	first := deriveCredentialBytes(key, devicePk, expiresAt)
	second := deriveCredentialBytes(key, devicePk, expiresAt)
	if !bytes.Equal(first, second) {
		t.Fatalf("deriveCredentialBytes not deterministic")
	}
}

// TestDeriveCredentialBytesDiffersAcrossDevices — load-bearing property
// of the HMAC binding: a credential issued to device A can't pass the
// VPN-server-side reverification when presented from device B.
func TestDeriveCredentialBytesDiffersAcrossDevices(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	expiresAt := "2026-05-27T13:00:00Z"

	credA := deriveCredentialBytes(key, "device-A", expiresAt)
	credB := deriveCredentialBytes(key, "device-B", expiresAt)
	if bytes.Equal(credA, credB) {
		t.Fatalf("same cred bytes for different devices — HMAC binding broken")
	}
}

// TestDeriveCredentialBytesDiffersAcrossExpiry — a cred issued for one
// expiry can't be replayed under a different claimed expiry.
func TestDeriveCredentialBytesDiffersAcrossExpiry(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	devicePk := "device-X"

	cred1 := deriveCredentialBytes(key, devicePk, "2026-05-27T13:00:00Z")
	cred2 := deriveCredentialBytes(key, devicePk, "2026-05-27T14:00:00Z")
	if bytes.Equal(cred1, cred2) {
		t.Fatalf("same cred bytes for different expiry — HMAC binding broken")
	}
}

// TestDeriveCredentialBytesDiffersAcrossHmacKeys — rotating the issuer's
// HMAC key invalidates every previously-issued credential.
func TestDeriveCredentialBytesDiffersAcrossHmacKeys(t *testing.T) {
	keyA := make([]byte, 32)
	rand.Read(keyA)
	keyB := make([]byte, 32)
	rand.Read(keyB)

	devicePk := "device-X"
	expiresAt := "2026-05-27T13:00:00Z"

	credA := deriveCredentialBytes(keyA, devicePk, expiresAt)
	credB := deriveCredentialBytes(keyB, devicePk, expiresAt)
	if bytes.Equal(credA, credB) {
		t.Fatalf("same cred bytes under different HMAC keys")
	}
}

// TestEncodeCredentialUuidV4Format — uuid-v4 encoding produces a string
// that's RFC 4122 shape (8-4-4-4-12 hex with the version + variant bits).
func TestEncodeCredentialUuidV4Format(t *testing.T) {
	bs := make([]byte, 32)
	rand.Read(bs)
	got, err := encodeCredential(credEncodingUuidV4, bs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(got) != 36 {
		t.Fatalf("uuid length = %d, want 36 (xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx)", len(got))
	}
	// Version nibble at index 14 must be '4'.
	if got[14] != '4' {
		t.Fatalf("version nibble = %q, want '4' (uuid: %s)", got[14], got)
	}
	// Variant nibble at index 19 must be 8 / 9 / a / b.
	switch got[19] {
	case '8', '9', 'a', 'b':
		// ok
	default:
		t.Fatalf("variant nibble = %q, want one of 8/9/a/b (uuid: %s)", got[19], got)
	}
}

// TestEncodeCredentialBase64UrlRaw — base64url-raw encoding round-trips
// to the original 32 bytes.
func TestEncodeCredentialBase64UrlRaw(t *testing.T) {
	bs := make([]byte, 32)
	rand.Read(bs)
	got, err := encodeCredential(credEncodingBase64UrlRaw, bs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	roundTrip, err := b64url.DecodeString(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(bs, roundTrip) {
		t.Fatalf("round trip mismatch")
	}
}

// TestEncodeCredentialEmptyDefaultsToBase64UrlRaw — back-compat ergonomics.
// An entry without credentialEncoding gets the safe-by-default opaque form.
func TestEncodeCredentialEmptyDefaultsToBase64UrlRaw(t *testing.T) {
	bs := make([]byte, 32)
	rand.Read(bs)
	got1, _ := encodeCredential("", bs)
	got2, _ := encodeCredential(credEncodingBase64UrlRaw, bs)
	if got1 != got2 {
		t.Fatalf("empty encoding should match base64url-raw")
	}
}

// TestEncodeCredentialUnknownReturnsError — typos surface as errors,
// not silent fallthrough.
func TestEncodeCredentialUnknownReturnsError(t *testing.T) {
	if _, err := encodeCredential("uuid-v3", make([]byte, 32)); err == nil {
		t.Fatalf("expected error on unknown encoding")
	}
}

// TestIssueRoundTripCredIsHmacDerived — end-to-end: drive POST /v1/issue
// against a registered uuid-v4 entry, decode the response's ConfigB64,
// and re-derive the expected UUID from the state's HMAC key. This is the
// contract a VPN-server-side validator would re-execute.
func TestIssueRoundTripCredIsHmacDerived(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"credentialEncoding": "uuid-v4",
		"config": {
			"name": "alpha",
			"address": "vpn:443",
			"type": "V2RAY",
			"v2rayProfile": {
				"server": "vpn",
				"serverPort": "443",
				"password": "$NPVT_CREDENTIAL$"
			}
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", httpResp.StatusCode, respBytes)
	}
	var resp IssueResponse
	json.Unmarshal(respBytes, &resp)

	// Re-derive what the VPN data plane would compute.
	hmacBytes := deriveCredentialBytes(state.VpnHmacKey, req.DevicePk, resp.ExpiresAt)
	expected, _ := encodeCredential(credEncodingUuidV4, hmacBytes)

	// Decode the issued ConfigBody and pull out the password field.
	cfg := decodeIssueResponseConfig(t, respBytes)
	profile, _ := cfg["v2rayProfile"].(map[string]any)
	got, _ := profile["password"].(string)
	if got != expected {
		t.Fatalf("password mismatch:\n  got      %s\n  expected %s", got, expected)
	}
}
