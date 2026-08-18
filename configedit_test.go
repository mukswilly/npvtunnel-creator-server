package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// Importing, replacing under the same configId, and removing a config all
// persist to configs.json, including app-selected policy changes.
func TestConsoleConfigReplaceRemove(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	id, err := c.appendConfig(json.RawMessage(`{"name":"a","type":"V2RAY","v2rayProfile":{"password":"old"}}`), registrationPolicy{})
	if err != nil {
		t.Fatalf("appendConfig: %v", err)
	}
	if err := c.setConfigDisplayName(id, "  My \n Alias   "); err != nil {
		t.Fatalf("set display name: %v", err)
	}

	// Replacing the body keeps the same configId; only the stored config changes.
	newBody := json.RawMessage(`{"name":"b","type":"SSH","sshConfig":{"sshHost":"h"}}`)
	newPolicy := registrationPolicy{onlyMobileNetwork: true}
	if err := c.replaceConfigRegistration(id, newBody, newPolicy); err != nil {
		t.Fatalf("replace: %v", err)
	}
	list, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if len(list) != 1 || list[0].ConfigID != id {
		t.Fatalf("expected 1 config with same id, got %+v", list)
	}
	if list[0].DisplayName != "My  Alias" || effectiveDisplayName(list[0]) != "My  Alias" {
		t.Errorf("display alias was not normalized and preserved: %+v", list[0])
	}
	var m map[string]any
	json.Unmarshal(list[0].Config, &m)
	if m["name"] != "b" || m["type"] != "SSH" {
		t.Errorf("replace didn't swap the body: %v", m)
	}
	if list[0].IssuedPolicy == nil || !list[0].IssuedPolicy.OnlyMobileNetwork {
		t.Errorf("replace didn't apply the imported policy: %+v", list[0].IssuedPolicy)
	}
	if err := c.setConfigDisplayName(id, ""); err != nil {
		t.Fatalf("clear display name: %v", err)
	}
	list, _ = readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if list[0].DisplayName != "" || effectiveDisplayName(list[0]) != "b" {
		t.Errorf("cleared alias should fall back to replacement config name: %+v", list[0])
	}

	if err := c.removeConfig(id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if list, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json")); len(list) != 0 {
		t.Errorf("expected empty registry after remove, got %d", len(list))
	}
	if err := c.removeConfig(id); err == nil {
		t.Error("expected not-found error on second remove")
	}
}

// decodeConfigRegistration accepts versioned app exports in plain or base64url
// form, carries their restrictions, and rejects bare config JSON.
func TestDecodeConfigRegistration(t *testing.T) {

	bundle := `{"kind":"npv-config-registration","v":1,"config":{"name":"a","type":"V2RAY","v2rayProfile":{"server":"vpn.example"}},` +
		`"blockRooted":true,"onlyMobileNetwork":true,"expiresAt":"2030-01-01T00:00:00Z","displayMessage":"hi"}`
	body, rp, err := decodeConfigRegistration(bundle)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if !rp.blockRooted || !rp.onlyMobileNetwork || rp.expiresAt != "2030-01-01T00:00:00Z" || rp.displayMessage != "hi" {
		t.Errorf("bundle policy not parsed: %+v", rp)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("bundle body not an object: %v", err)
	}
	if m["type"] != "V2RAY" || m["name"] != "a" {
		t.Errorf("bundle body = %v, want the inner config", m)
	}
	if _, ok := m["kind"]; ok {
		t.Error("bundle body must not carry the registration wrapper fields")
	}

	// A populated policy maps to a non-nil issued policy carrying the restrictions forward.
	if ip := issuedPolicyFrom(rp); ip == nil || !ip.OnlyMobileNetwork || ip.ExpiresAt == nil {
		t.Errorf("issuedPolicyFrom dropped restrictions: %+v", ip)
	}

	// The same bundle is accepted base64url-encoded.
	if _, rp2, err := decodeConfigRegistration(b64url.EncodeToString([]byte(bundle))); err != nil || !rp2.blockRooted {
		t.Errorf("base64 bundle: blockRooted=%v err=%v", rp2.blockRooted, err)
	}

	// The app's iOS identity rides along so the strict policy can carry an App
	// Attest arm; without it there is no way to verify an iPhone.
	iosBundle := `{"kind":"npv-config-registration","v":1,"config":{"name":"a","type":"V2RAY","v2rayProfile":{"server":"vpn.example"}},` +
		`"blockRooted":true,"iosAppId":"TEAMID.com.example.app"}`
	_, rpIOS, err := decodeConfigRegistration(iosBundle)
	if err != nil {
		t.Fatalf("ios bundle: %v", err)
	}
	if rpIOS.iosAppID != "TEAMID.com.example.app" {
		t.Errorf("iosAppID = %q, want it carried out of the bundle", rpIOS.iosAppID)
	}
	if arm, ok := strictDeviceAttestationPolicy(rpIOS.iosAppID).armFor("IOS"); !ok || arm.AppID != rpIOS.iosAppID {
		t.Errorf("ios arm = %+v ok=%v, want the bundle's appId", arm, ok)
	}
	// A bundle without iosAppId produces an Android-only strict policy.
	if !rp.blockRooted || rp.iosAppID != "" {
		t.Errorf("bundle without iosAppId should leave it empty: %+v", rp)
	}
	if _, ok := strictDeviceAttestationPolicy(rp.iosAppID).armFor("IOS"); ok {
		t.Error("no iosAppId must mean no iOS arm")
	}

	if _, _, err := decodeConfigRegistration(`{"type":"SSH","sshConfig":{"sshHost":"h"}}`); err == nil {
		t.Error("bare config JSON must be rejected")
	}
	if _, _, err := decodeConfigRegistration(`{"kind":"npv-config-registration","v":2,"config":{"type":"SSH","sshConfig":{"sshHost":"h"}}}`); err == nil {
		t.Error("unsupported registration versions must be rejected")
	}
	if _, _, err := decodeConfigRegistration(`{"kind":"npv-config-registration","v":1,"config":{"type":"V2RAY"}}`); err == nil {
		t.Error("a registration without the app's protocol payload must be rejected")
	}
}

// handoutFilename builds the .npvs handout path from truncated configId and pubkey prefixes.
func TestHandoutFilename(t *testing.T) {
	got := handoutFilename("/s", "configIdLong123456", "pubKeyLong123456")
	want := filepath.Join("/s", "handout-configId-pubKeyLo.npvs")
	if got != want {
		t.Errorf("handoutFilename = %q, want %q", got, want)
	}
}
