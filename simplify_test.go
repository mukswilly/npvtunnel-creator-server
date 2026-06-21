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
	"time"
)

// TestIssueAlwaysOnRateLimit verifies the issuance rate limit is enforced
// even with NO attestation policy configured (the default deployment). The
// pre-change behavior left a policy-off issuer completely unthrottled.
func TestIssueAlwaysOnRateLimit(t *testing.T) {
	_, _, ts := newTestServer(t) // no config registry → stub path, no policy
	defer ts.Close()

	devPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen device key: %v", err)
	}
	req := IssueRequest{
		V:        1,
		DevicePk: compressP256ToB64(t, &devPriv.PublicKey),
		Attestation: AttestationBlob{
			Platform: "NONE", Nonce: b64url.EncodeToString(randomBytes(t, 16)),
		},
		ConfigID:     b64url.EncodeToString(randomBytes(t, 16)),
		RequestNonce: b64url.EncodeToString(randomBytes(t, 16)),
	}
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))
	body, _ := json.Marshal(req) // replayable — same bytes, valid signature each time

	var ok, limited int
	for i := 0; i < defaultIssuanceLimitPerHour+5; i++ {
		resp, err := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if ok != defaultIssuanceLimitPerHour {
		t.Fatalf("expected %d OK, got %d (limited=%d)", defaultIssuanceLimitPerHour, ok, limited)
	}
	if limited != 5 {
		t.Fatalf("expected 5 rate-limited, got %d", limited)
	}
}

// TestReloadConfigsIfChanged verifies configs.json hot-reload picks up new
// entries on an mtime bump, and that a malformed edit keeps the last-good
// registry live instead of taking the issuer down.
func TestReloadConfigsIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "configs.json")
	id1 := b64url.EncodeToString(randomBytes(t, envelopeConfigIDLen))
	id2 := b64url.EncodeToString(randomBytes(t, envelopeConfigIDLen))

	if err := writeConfigEntries(path, []ConfigEntry{
		{ConfigID: id1, Config: json.RawMessage(`{"name":"a","type":"V2RAY"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	state, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	if state.ConfigByID(id1) == nil {
		t.Fatal("id1 should be registered at startup")
	}

	// Add a second entry; bump mtime so the reload triggers.
	if err := writeConfigEntries(path, []ConfigEntry{
		{ConfigID: id1, Config: json.RawMessage(`{"name":"a","type":"V2RAY"}`)},
		{ConfigID: id2, Config: json.RawMessage(`{"name":"b","type":"SSH"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path, 2)
	if err := state.ReloadConfigsIfChanged(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if state.ConfigByID(id2) == nil {
		t.Fatal("id2 should be registered after hot-reload")
	}

	// A malformed edit must NOT clobber the live registry.
	if err := os.WriteFile(path, []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path, 4)
	if err := state.ReloadConfigsIfChanged(); err == nil {
		t.Fatal("expected an error reloading malformed configs.json")
	}
	if state.ConfigByID(id1) == nil || state.ConfigByID(id2) == nil {
		t.Fatal("last-good registry must survive a malformed edit")
	}
}

// TestTokenStatus covers the share-link status classification used by
// `token ls` / `status`.
func TestTokenStatus(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		tok  RedemptionToken
		want tokenStatusCode
	}{
		{"exhausted", RedemptionToken{RemainingRedemptions: 0, ExpiresAt: ""}, statusExhausted},
		{"expired", RedemptionToken{RemainingRedemptions: 5, ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}, statusExpired},
		{"expiring", RedemptionToken{RemainingRedemptions: 5, ExpiresAt: now.Add(6 * time.Hour).Format(time.RFC3339)}, statusExpiring},
		{"live-no-expiry", RedemptionToken{RemainingRedemptions: 5, ExpiresAt: ""}, statusLive},
		{"live-far-expiry", RedemptionToken{RemainingRedemptions: 5, ExpiresAt: now.Add(72 * time.Hour).Format(time.RFC3339)}, statusLive},
	}
	for _, c := range cases {
		if _, got := tokenStatus(c.tok, now); got != c.want {
			t.Errorf("%s: got status code %d, want %d", c.name, got, c.want)
		}
	}
}

// TestDecodeConfigString covers `config add` accepting the app's exported
// config string — base64url of the config body OR raw JSON — without the
// creator hand-writing the format.
func TestDecodeConfigString(t *testing.T) {
	bodyJSON := `{"name":"x","address":"h:443","type":"V2RAY","v2rayProfile":{"server":"h","serverPort":"443","password":"npvs1:AAAA"}}`
	b64 := b64url.EncodeToString([]byte(bodyJSON)) // the app's export form

	for _, in := range []string{b64, bodyJSON, "  " + b64 + "  "} {
		got, err := decodeConfigString(in)
		if err != nil {
			t.Fatalf("decodeConfigString(%.16q...): %v", in, err)
		}
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("result is not a JSON object: %v", err)
		}
		if m["type"] != "V2RAY" {
			t.Fatalf("type = %v, want V2RAY", m["type"])
		}
	}

	for _, bad := range []string{
		"",                // empty
		"not base64 %%%%", // not JSON, not base64
		"[1,2,3]",         // JSON but not an object
		"e30",             // base64url of "{}" — empty object
	} {
		if _, err := decodeConfigString(bad); err == nil {
			t.Errorf("decodeConfigString(%q): expected error, got nil", bad)
		}
	}
}

func bumpMtime(t *testing.T, path string, secs int) {
	t.Helper()
	ft := time.Now().Add(time.Duration(secs) * time.Second)
	if err := os.Chtimes(path, ft, ft); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}
