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

// /v1/issue is rate-limited even with no attestation policy: exactly the default
// per-hour quota succeeds and the overflow returns 429.
func TestIssueAlwaysOnRateLimit(t *testing.T) {
	_, _, ts := newTestServer(t)
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
	body, _ := json.Marshal(req)

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

// Reloading picks up newly added configs after the file changes, and a malformed
// edit is rejected while the last-good registry stays intact.
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

	if err := writeConfigEntries(path, []ConfigEntry{
		{ConfigID: id1, Config: json.RawMessage(`{"name":"a","type":"V2RAY"}`)},
		{ConfigID: id2, Config: json.RawMessage(`{"name":"b","type":"SSH"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path, 2) // reload keys off mtime, so advance it
	if err := state.ReloadConfigsIfChanged(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if state.ConfigByID(id2) == nil {
		t.Fatal("id2 should be registered after hot-reload")
	}

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

// tokenStatus classifies a token as exhausted, expired, expiring soon, or live.
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

// decodeConfigString accepts a config as base64url or raw JSON (with surrounding
// whitespace tolerated) and rejects empty, non-decodable, or non-object input.
func TestDecodeConfigString(t *testing.T) {
	bodyJSON := `{"name":"x","address":"h:443","type":"V2RAY","v2rayProfile":{"server":"h","serverPort":"443","password":"npvs1:AAAA"}}`
	b64 := b64url.EncodeToString([]byte(bodyJSON))

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
		"",
		"not base64 %%%%",
		"[1,2,3]",
		"e30",
	} {
		if _, err := decodeConfigString(bad); err == nil {
			t.Errorf("decodeConfigString(%q): expected error, got nil", bad)
		}
	}
}

// Every console screen can be constructed without panicking and registers its
// page, including the per-config action screens reached from a registered config.
func TestConsoleBuilds(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	if !c.pages.HasPage("main") {
		t.Fatal("console is missing its main page after construction")
	}

	c.showAddConfig()
	if !c.pages.HasPage("addconfig") {
		t.Fatal("addconfig page missing")
	}

	// The server screen probes these dependencies, so stub them first.
	c.svc = &fakeController{}
	c.health = fakeHealth{}
	c.port = fakePort{}
	c.cert = fakeCert{}
	c.showServer()
	if !c.pages.HasPage("server") {
		t.Fatal("server page missing")
	}
	c.showLogs()
	if !c.pages.HasPage("logs") {
		t.Fatal("logs page missing")
	}
	c.showSetupWizard()
	if !c.pages.HasPage("setup") {
		t.Fatal("setup page missing")
	}

	c.showConfigs()
	c.showTokens()
	c.showMint("")
	c.showBackup()

	id, err := c.appendConfig([]byte(`{"name":"x","type":"V2RAY","v2rayProfile":{"password":"p"}}`), registrationPolicy{})
	if err != nil {
		t.Fatalf("appendConfig: %v", err)
	}
	for _, tc := range []struct {
		page string
		open func()
	}{
		{"configs", c.showConfigs},
		{"mint", func() { c.showMint("") }},
		{"configactions", func() { c.showConfigActions(id) }},
		{"directmint", func() { c.showDirectMint(id) }},
		{"replace", func() { c.showReplaceConfig(id) }},
	} {
		tc.open()
		if !c.pages.HasPage(tc.page) {
			t.Fatalf("%s page missing", tc.page)
		}
	}
}

// bumpMtime advances a file's modification time so a change is detected.
func bumpMtime(t *testing.T, path string, secs int) {
	t.Helper()
	ft := time.Now().Add(time.Duration(secs) * time.Second)
	if err := os.Chtimes(path, ft, ft); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}
