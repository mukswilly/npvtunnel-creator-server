package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// randomRecipientB64 returns a fresh P-256 compressed pubkey as
// base64url-no-pad — the shape `mint -recipient-pubkey` accepts.
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

// TestMintSubcommandCollectsRecipientsAcrossForms exercises the CLI
// recipient-collection layer: a single -recipient-pubkey, a repeated
// one, a comma-separated list in one flag, and a -recipient-pubkeys-file
// all contribute, and duplicates are deduped. The minted envelope's
// recipient count is the observable proof.
func TestMintSubcommandCollectsRecipientsAcrossForms(t *testing.T) {
	dir := t.TempDir()

	a := randomRecipientB64(t)
	b := randomRecipientB64(t)
	c := randomRecipientB64(t)
	d := randomRecipientB64(t)

	// d goes in via a file, one per line.
	pubkeyFile := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(pubkeyFile, []byte(d+"\n"), 0o600); err != nil {
		t.Fatalf("write recipients file: %v", err)
	}

	outFile := filepath.Join(dir, "out.npvs")
	code := runMintSubcommand([]string{
		"-state-dir", dir,
		"-issuer-url", "https://issuer.test/v1/issue",
		"-recipient-pubkey", a, // single flag
		"-recipient-pubkey", b + "," + c, // comma list in one flag
		"-recipient-pubkey", a, // exact duplicate of a — must dedup
		"-recipient-pubkeys-file", pubkeyFile, // d from file
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
	// a, b, c, d distinct → 4 recipients (the second `a` deduped away).
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

// TestMintSubcommandRequiresAtLeastOneRecipient — with no recipient flag
// or file, the subcommand refuses rather than minting an empty envelope.
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
