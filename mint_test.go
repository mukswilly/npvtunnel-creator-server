package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// randomRecipientB64 returns a fresh compressed P-256 public key, base64url-encoded.
func randomRecipientB64(t *testing.T) string {
	t.Helper()
	p, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}
	compressed, err := compressUncompressedP256(p.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	return b64url.EncodeToString(compressed)
}

// Recipients may arrive via repeated flags, comma-separated lists, and a file;
// all forms are merged and duplicates collapsed to one envelope recipient each.
func TestMintSubcommandCollectsRecipientsAcrossForms(t *testing.T) {
	dir := t.TempDir()

	a := randomRecipientB64(t)
	b := randomRecipientB64(t)
	c := randomRecipientB64(t)
	d := randomRecipientB64(t)

	pubkeyFile := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(pubkeyFile, []byte(d+"\n"), 0o600); err != nil {
		t.Fatalf("write recipients file: %v", err)
	}

	outFile := filepath.Join(dir, "out.npvs")
	// a (twice) + b,c + d-from-file = four distinct recipients after dedup.
	code := runMintSubcommand([]string{
		"-state-dir", dir,
		"-issuer-url", "https://issuer.test/v1/issue",
		"-recipient-pubkey", a,
		"-recipient-pubkey", b + "," + c,
		"-recipient-pubkey", a,
		"-recipient-pubkeys-file", pubkeyFile,
		"-out", outFile,
	})
	if code != 0 {
		t.Fatalf("runMintSubcommand exit = %d, want 0", code)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	dec, err := decodeEnvelopeWire(raw)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	if len(dec.Header.Recipients) != 4 {
		t.Fatalf("recipients = %d, want 4 (deduped)", len(dec.Header.Recipients))
	}
	seen := map[string]bool{}
	for _, r := range dec.Header.Recipients {
		if seen[r.Fp] {
			t.Errorf("duplicate recipient fp survived dedup: %s", r.Fp)
		}
		seen[r.Fp] = true
	}
}

// Minting with no recipients in any form exits non-zero.
func TestMintSubcommandRequiresAtLeastOneRecipient(t *testing.T) {
	dir := t.TempDir()
	code := runMintSubcommand([]string{
		"-state-dir", dir,
		"-issuer-url", "https://issuer.test/v1/issue",
	})
	if code == 0 {
		t.Fatalf("expected non-zero exit when no recipients supplied")
	}
}
