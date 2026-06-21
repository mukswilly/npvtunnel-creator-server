package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestConsoleConfigReplaceRemove(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	id, err := c.appendConfig(json.RawMessage(`{"name":"a","type":"V2RAY","v2rayProfile":{"password":"old"}}`))
	if err != nil {
		t.Fatalf("appendConfig: %v", err)
	}

	// Replace the whole config body; the configId must be preserved so existing
	// share links / handout files keep resolving.
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
