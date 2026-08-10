package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFilePreservesExistingOwnershipAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "configs.json")
	if err := os.WriteFile(path, []byte("before"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeUID, beforeGID, beforeHasOwner := fileOwner(before)
	oldHandle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer oldHandle.Close()

	if err := atomicWriteFile(path, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode changed to %04o, want 0640", got)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "after" {
		t.Fatalf("replacement contents = %q, err=%v", got, err)
	}
	oldContents, err := os.ReadFile(oldHandle.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(oldContents) != "after" {
		t.Fatalf("named path did not expose replacement contents: %q", oldContents)
	}
	if _, err := oldHandle.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	oldBytes := make([]byte, len("before"))
	if _, err := oldHandle.Read(oldBytes); err != nil {
		t.Fatal(err)
	}
	if string(oldBytes) != "before" {
		t.Fatalf("open pre-replacement handle changed in place: %q", oldBytes)
	}
	if afterUID, afterGID, ok := fileOwner(after); beforeHasOwner &&
		(!ok || afterUID != beforeUID || afterGID != beforeGID) {
		t.Fatalf("ownership changed from %d:%d to %d:%d", beforeUID, beforeGID, afterUID, afterGID)
	}
}

func TestAtomicWriteFileCreatesOwnerOnlyState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redemption-tokens.json")
	if err := atomicWriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileUID, fileGID, fileOK := fileOwner(info)
	dirUID, dirGID, dirOK := fileOwner(dirInfo)
	if fileOK && dirOK && (fileUID != dirUID || fileGID != dirGID) {
		t.Fatalf("new file owner %d:%d does not match state directory %d:%d", fileUID, fileGID, dirUID, dirGID)
	}
}
