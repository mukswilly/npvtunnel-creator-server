package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// Appending, in-place replacing (same configId), and removing a config all persist to configs.json,
// and removing an absent id is an error.
func TestConsoleConfigReplaceRemove(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	id, err := c.appendConfig(json.RawMessage(`{"name":"a","type":"V2RAY","v2rayProfile":{"password":"old"}}`), registrationPolicy{})
	if err != nil {
		t.Fatalf("appendConfig: %v", err)
	}

	// Replacing the body keeps the same configId; only the stored config changes.
	newBody := json.RawMessage(`{"name":"b","type":"SSH","sshConfig":{"sshHost":"h"}}`)
	if err := c.updateConfigBody(id, func(json.RawMessage) (json.RawMessage, error) {
		return newBody, nil
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	list, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if len(list) != 1 || list[0].ConfigID != id {
		t.Fatalf("expected 1 config with same id, got %+v", list)
	}
	var m map[string]any
	json.Unmarshal(list[0].Config, &m)
	if m["name"] != "b" || m["type"] != "SSH" {
		t.Errorf("replace didn't swap the body: %v", m)
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

// decodeConfigRegistration handles a registration bundle (plain or base64url), unwrapping the inner
// config and its use-restriction policy, and treats a bare config body as a zero policy.
func TestDecodeConfigRegistration(t *testing.T) {

	bundle := `{"kind":"npv-config-registration","v":1,"config":{"name":"a","type":"V2RAY"},` +
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

	body2, rp3, err := decodeConfigRegistration(`{"type":"SSH","sshConfig":{"sshHost":"h"}}`)
	if err != nil {
		t.Fatalf("bare: %v", err)
	}
	if rp3.blockRooted || issuedPolicyFrom(rp3) != nil {
		t.Error("bare body must default to a zero policy")
	}
	json.Unmarshal(body2, &m)
	if m["type"] != "SSH" {
		t.Errorf("bare body = %v", m)
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
