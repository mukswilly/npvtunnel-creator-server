package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestSetConfigCredential(t *testing.T) {
	// V2RAY → v2rayProfile.password, other fields preserved.
	out, err := setConfigCredential(
		json.RawMessage(`{"name":"a","type":"V2RAY","v2rayProfile":{"server":"s","password":"old"}}`), "new")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	prof := m["v2rayProfile"].(map[string]any)
	if prof["password"] != "new" {
		t.Errorf("password = %v, want new", prof["password"])
	}
	if prof["server"] != "s" || m["name"] != "a" {
		t.Errorf("other fields not preserved: %v", m)
	}

	// SSH → sshConfig.sshPassword.
	out, err = setConfigCredential(
		json.RawMessage(`{"type":"SSH","sshConfig":{"sshHost":"h","sshPassword":"old"}}`), "newpw")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &m)
	sc := m["sshConfig"].(map[string]any)
	if sc["sshPassword"] != "newpw" || sc["sshHost"] != "h" {
		t.Errorf("ssh rotate wrong: %v", sc)
	}

	if _, err := setConfigCredential(json.RawMessage(`{"type":"WG"}`), "x"); err == nil {
		t.Error("expected error for unknown config type")
	}
	if _, err := setConfigCredential(json.RawMessage(`[1,2]`), "x"); err == nil {
		t.Error("expected error for non-object body")
	}
}

func TestSetConfigName(t *testing.T) {
	out, err := setConfigName(
		json.RawMessage(`{"name":"old","type":"V2RAY","v2rayProfile":{"server":"s"}}`), "new")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(out, &m)
	if m["name"] != "new" {
		t.Errorf("name = %v, want new", m["name"])
	}
	if m["type"] != "V2RAY" {
		t.Error("type field lost on rename")
	}
}

func TestConsoleConfigCRUD(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	id, err := c.appendConfig(json.RawMessage(`{"name":"a","type":"V2RAY","v2rayProfile":{"password":"old"}}`))
	if err != nil {
		t.Fatalf("appendConfig: %v", err)
	}

	// Rotate the credential and confirm it landed.
	if err := c.updateConfigBody(id, func(b json.RawMessage) (json.RawMessage, error) {
		return setConfigCredential(b, "new")
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	list, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if len(list) != 1 {
		t.Fatalf("expected 1 config, got %d", len(list))
	}
	var m map[string]any
	json.Unmarshal(list[0].Config, &m)
	if m["v2rayProfile"].(map[string]any)["password"] != "new" {
		t.Errorf("rotate didn't persist: %v", m)
	}

	// Remove, then a second remove should report not-found.
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

func TestHandoutFilename(t *testing.T) {
	got := handoutFilename("/s", "configIdLong123456", "pubKeyLong123456")
	want := filepath.Join("/s", "handout-configId-pubKeyLo.npvs")
	if got != want {
		t.Errorf("handoutFilename = %q, want %q", got, want)
	}
}
