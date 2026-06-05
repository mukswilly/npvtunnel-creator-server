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
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────
// deepMergeConfigBody — pure function
// ──────────────────────────────────────────────────────────────────

// TestDeepMergeBaseOnly — no variant means the base passes through verbatim.
func TestDeepMergeBaseOnly(t *testing.T) {
	base := json.RawMessage(`{"type":"V2RAY","v2rayProfile":{"server":"vpn.example"}}`)
	got, err := deepMergeConfigBody(base, nil)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !bytes.Equal(got, base) {
		t.Fatalf("got %s, want unchanged base", got)
	}
}

// TestDeepMergeVariantOnly — a variant with no base IS the config.
func TestDeepMergeVariantOnly(t *testing.T) {
	variant := json.RawMessage(`{"type":"SSH","sshConfig":{"sshHost":"vpn"}}`)
	got, err := deepMergeConfigBody(nil, variant)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !bytes.Equal(got, variant) {
		t.Fatalf("got %s, want unchanged variant", got)
	}
}

// TestDeepMergeOverridesNestedLeaf — the load-bearing case for
// watermarking. Variant overrides v2rayProfile.shortId; every other
// field falls through.
func TestDeepMergeOverridesNestedLeaf(t *testing.T) {
	base := json.RawMessage(`{
		"name": "test",
		"address": "vpn.example:443",
		"type": "V2RAY",
		"v2rayProfile": {
			"server": "vpn.example",
			"serverPort": "443",
			"password": "$NPVT_CREDENTIAL$",
			"shortId": "baseId",
			"publicKey": "shared-pk"
		}
	}`)
	variant := json.RawMessage(`{"v2rayProfile":{"shortId":"variantId"}}`)

	got, err := deepMergeConfigBody(base, variant)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var asMap map[string]any
	json.Unmarshal(got, &asMap)
	profile, _ := asMap["v2rayProfile"].(map[string]any)
	if profile["shortId"] != "variantId" {
		t.Errorf("shortId should be variantId, got %v", profile["shortId"])
	}
	if profile["publicKey"] != "shared-pk" {
		t.Errorf("publicKey should fall through, got %v", profile["publicKey"])
	}
	if profile["server"] != "vpn.example" {
		t.Errorf("server should fall through, got %v", profile["server"])
	}
	if asMap["address"] != "vpn.example:443" {
		t.Errorf("address should fall through, got %v", asMap["address"])
	}
}

// TestDeepMergeScalarReplacesObject — when the variant value at a path
// is a scalar and the base value at the same path is an object, the
// scalar replaces wholesale. (Documents the behavior even if it's an
// unusual operator move — most variants are object-shaped.)
func TestDeepMergeScalarReplacesObject(t *testing.T) {
	base := json.RawMessage(`{"v2rayProfile":{"server":"a"}}`)
	variant := json.RawMessage(`{"v2rayProfile":"not-an-object"}`)
	got, err := deepMergeConfigBody(base, variant)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var asMap map[string]any
	json.Unmarshal(got, &asMap)
	if asMap["v2rayProfile"] != "not-an-object" {
		t.Errorf("scalar should replace, got %v", asMap["v2rayProfile"])
	}
}

// ──────────────────────────────────────────────────────────────────
// configs.json validation
// ──────────────────────────────────────────────────────────────────

// TestConfigsFileLoadRejectsNonObjectVariant — load-time guard against
// operator footguns. A scalar in the variants map breaks the deep
// merge contract.
func TestConfigsFileLoadRejectsNonObjectVariant(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "x",
		"credentialEncoding": "base64url-raw",
		"config": {"type":"V2RAY","v2rayProfile":{"password":"$NPVT_CREDENTIAL$"}},
		"recipientVariants": {
			"device-X": "not-an-object"
		}
	}]`
	if err := os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected load failure on non-object variant")
	}
	if !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("expected 'not a JSON object' message, got: %v", err)
	}
}

// TestConfigsFileLoadRejectsMissingConfig — registered entries must
// supply a Config template. Forgotten field gets caught at startup.
func TestConfigsFileLoadRejectsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "x"
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
		"vpnProtocol": "x",
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

// ──────────────────────────────────────────────────────────────────
// End-to-end watermarking through /v1/issue
// ──────────────────────────────────────────────────────────────────

// TestIssueAppliesRecipientVariantForMatchingDevice — end-to-end:
// the response's decoded ConfigBody reflects the variant override
// for the requesting devicePk.
func TestIssueAppliesRecipientVariantForMatchingDevice(t *testing.T) {
	dir := t.TempDir()

	// Generate the device key first so we can encode its pubkey into
	// the variants map.
	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "xray-vless-reality",
		"credentialEncoding": "uuid-v4",
		"config": {
			"name": "alpha",
			"address": "vpn-a.example:443",
			"type": "V2RAY",
			"v2rayProfile": {
				"server": "vpn-a.example",
				"serverPort": "443",
				"password": "$NPVT_CREDENTIAL$",
				"sni": "google.com",
				"publicKey": "shared-pk",
				"shortId": "ffffffff"
			}
		},
		"recipientVariants": {
			"` + devPkB64 + `": { "v2rayProfile": { "shortId": "deadbeef" } }
		}
	}]`
	if err := os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600); err != nil {
		t.Fatalf("write configs: %v", err)
	}

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init state: %v", err)
	}
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", httpResp.StatusCode, respBytes)
	}

	cfg := decodeIssueResponseConfig(t, respBytes)
	profile, _ := cfg["v2rayProfile"].(map[string]any)
	if profile["sni"] != "google.com" {
		t.Errorf("base field sni should pass through, got %v", profile["sni"])
	}
	if profile["publicKey"] != "shared-pk" {
		t.Errorf("base field publicKey should pass through, got %v", profile["publicKey"])
	}
	if profile["shortId"] != "deadbeef" {
		t.Errorf("shortId should be variant 'deadbeef', got %v", profile["shortId"])
	}
	// And the credential slot got substituted with a UUID-shaped string,
	// not the literal sentinel.
	if profile["password"] == credentialSentinel {
		t.Errorf("password sentinel was not substituted")
	}
	if pw, _ := profile["password"].(string); !strings.Contains(pw, "-") {
		t.Errorf("password should look like a UUID, got %v", profile["password"])
	}
}

// TestIssueFallsThroughToBaseForUnvariantedDevice — a device that's not
// in the variants map gets the base Config unchanged (apart from the
// credential substitution).
func TestIssueFallsThroughToBaseForUnvariantedDevice(t *testing.T) {
	dir := t.TempDir()

	variantDev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	variantDevPkB64 := compressP256ToB64(t, &variantDev.PublicKey)
	requesterDev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"vpnProtocol": "xray-vless-reality",
		"credentialEncoding": "uuid-v4",
		"config": {
			"type": "V2RAY",
			"v2rayProfile": {
				"password": "$NPVT_CREDENTIAL$",
				"shortId": "baseId"
			}
		},
		"recipientVariants": {"` + variantDevPkB64 + `": {"v2rayProfile":{"shortId":"variantId"}}}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)

	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	req := buildSignedIssueRequest(t, requesterDev, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)

	cfg := decodeIssueResponseConfig(t, respBytes)
	profile, _ := cfg["v2rayProfile"].(map[string]any)
	if profile["shortId"] != "baseId" {
		t.Errorf("unvarianted device should get base shortId, got %v", profile["shortId"])
	}
}

// ──────────────────────────────────────────────────────────────────
// Revocation
// ──────────────────────────────────────────────────────────────────

// TestRevocationFileMissingMeansNoRevocations — back-compat for
// deployments that never set up revoked.json.
func TestRevocationFileMissingMeansNoRevocations(t *testing.T) {
	dir := t.TempDir()
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if state.IsRevoked("any-device") != nil {
		t.Fatalf("expected nil for missing revoked.json")
	}
}

// TestIssueBlocksRevokedDevice — end-to-end 403 for a revoked device.
func TestIssueBlocksRevokedDevice(t *testing.T) {
	dir := t.TempDir()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devPkB64 := compressP256ToB64(t, &devPriv.PublicKey)

	revoked := `[{
		"devicePk": "` + devPkB64 + `",
		"revokedAt": "2026-05-27T12:00:00Z",
		"reason": "test"
	}]`
	os.WriteFile(filepath.Join(dir, "revoked.json"), []byte(revoked), 0o600)

	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if state.IsRevoked(devPkB64) == nil {
		t.Fatalf("revocation not loaded")
	}

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()
	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked device, got %d: %s", httpResp.StatusCode, respBytes)
	}
	if !strings.Contains(string(respBytes), "device_revoked") {
		t.Fatalf("expected device_revoked error code: %s", respBytes)
	}
}

// TestRevocationLoadRejectsDuplicateDevicePk — operator footgun guard.
func TestRevocationLoadRejectsDuplicateDevicePk(t *testing.T) {
	dir := t.TempDir()
	raw := `[
		{"devicePk":"dup","revokedAt":"2026-05-27","reason":"a"},
		{"devicePk":"dup","revokedAt":"2026-05-27","reason":"b"}
	]`
	os.WriteFile(filepath.Join(dir, "revoked.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected duplicate devicePk error")
	}
}

// TestRevocationCheckRunsAfterSignatureVerify — a request with a bad
// signature gets 401, not 403, even if its claimed devicePk is in the
// revocation list. Otherwise an attacker could probe revocation status
// for arbitrary pubkeys.
func TestRevocationCheckRunsAfterSignatureVerify(t *testing.T) {
	dir := t.TempDir()

	fakePk := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	revoked := `[{"devicePk":"` + fakePk + `","reason":"test"}]`
	os.WriteFile(filepath.Join(dir, "revoked.json"), []byte(revoked), 0o600)

	state, _ := NewStateWithDir(dir)
	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.DevicePk = fakePk

	body, _ := json.Marshal(req)
	httpResp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusForbidden {
		t.Fatalf("revocation status leaked before signature verify — got 403 on tampered request")
	}
}

// TestRevocationListIsLoadedFromDisk — the load+lookup round-trip,
// independent of the HTTP plumbing.
func TestRevocationListIsLoadedFromDisk(t *testing.T) {
	dir := t.TempDir()
	raw := `[
		{"devicePk":"alice","reason":"reason-a"},
		{"devicePk":"bob","reason":"reason-b"}
	]`
	os.WriteFile(filepath.Join(dir, "revoked.json"), []byte(raw), 0o600)
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	alice := state.IsRevoked("alice")
	if alice == nil || alice.Reason != "reason-a" {
		t.Fatalf("alice lookup failed: %+v", alice)
	}
	bob := state.IsRevoked("bob")
	if bob == nil || bob.Reason != "reason-b" {
		t.Fatalf("bob lookup failed: %+v", bob)
	}
	if state.IsRevoked("carol") != nil {
		t.Fatalf("carol should not be revoked")
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
