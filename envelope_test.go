package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"crypto/aes"
	"crypto/cipher"
	"io"
)

// ─── canonical JSON ───────────────────────────────────────────────

func TestCanonicalJSONSortsKeys(t *testing.T) {
	in := map[string]any{"c": 3, "a": 1, "b": 2}
	out, err := canonicalJSON(in)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if string(out) != `{"a":1,"b":2,"c":3}` {
		t.Errorf("got %s", out)
	}
}

func TestCanonicalJSONNestedSorting(t *testing.T) {
	in := map[string]any{
		"z": map[string]any{"y": 1, "x": 2},
		"a": []any{map[string]any{"q": 1, "p": 2}, "str", true, nil},
	}
	out, _ := canonicalJSON(in)
	want := `{"a":[{"p":2,"q":1},"str",true,null],"z":{"x":2,"y":1}}`
	if string(out) != want {
		t.Errorf("got %s\nwant %s", out, want)
	}
}

func TestCanonicalJSONEscapesControlChars(t *testing.T) {
	in := map[string]any{"k": "a\nb\tc\"d\\e\x01f"}
	out, _ := canonicalJSON(in)
	// \x01 in input renders as the  escape per RFC 8259, matching
	// the documented wire format (lowercase hex padded to 4 digits).
	want := "{\"k\":\"a\\nb\\tc\\\"d\\\\e\\u0001f\"}"
	if string(out) != want {
		t.Errorf("got %s\nwant %s", out, want)
	}
}

func TestCanonicalJSONFromTypedStructPreservesIntegers(t *testing.T) {
	type policy struct {
		OnlyMobileNetwork bool    `json:"onlyMobileNetwork"`
		ExpiresAt         *string `json:"expiresAt"`
	}
	type hdr struct {
		V      int    `json:"v"`
		ID     string `json:"id"`
		Policy policy `json:"policy"`
	}
	out, err := canonicalJSONOfStruct(hdr{V: 1, ID: "abc", Policy: policy{OnlyMobileNetwork: true, ExpiresAt: nil}})
	if err != nil {
		t.Fatalf("canonicalJSONOfStruct: %v", err)
	}
	// Keys must sort, integer must be `1` not `1.0`, nil pointer
	// renders as `null` (not omitted), bool renders true.
	want := `{"id":"abc","policy":{"expiresAt":null,"onlyMobileNetwork":true},"v":1}`
	if string(out) != want {
		t.Errorf("got %s\nwant %s", out, want)
	}
}

// ─── P-256 helpers ────────────────────────────────────────────────

func TestCompressDecompressRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compressed, err := compressP256(&priv.PublicKey)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(compressed) != 33 {
		t.Fatalf("len = %d, want 33", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Errorf("prefix 0x%02x not in {0x02, 0x03}", compressed[0])
	}
	// Decompress back via the ecdh helper to confirm it round-trips
	// to a usable point (decoder rejects invalid points).
	if _, err := decodeP256CompressedToEcdh(compressed); err != nil {
		t.Errorf("decompress failed: %v", err)
	}
}

// ─── KEM wrap ↔ unwrap round trip ─────────────────────────────────
//
// Independent re-implementation of the envelope RECEIVER (unwrap) step
// (a recipient's unwrap routine, in pure Go for testing).
// Confirms the minter's wrap step produces bytes that the documented
// receiver flow can recover the DEK from.

func TestEcdhEphemeralWrapRoundTrip(t *testing.T) {
	recipientPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey().Bytes() // 65-byte uncompressed
	recipientPubCompressed, err := compressUncompressedP256(recipientPub)
	if err != nil {
		t.Fatalf("compress recipient pub: %v", err)
	}

	configID := bytes.Repeat([]byte{0x42}, 16)
	dek := bytes.Repeat([]byte{0xAB}, 32)
	wrap, fp, err := ecdhEphemeralWrap(recipientPubCompressed, configID, dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(wrap) != 93 {
		t.Fatalf("wrap len = %d, want 93", len(wrap))
	}
	expectedFp := sha256.Sum256(recipientPubCompressed)
	if !bytes.Equal(fp, expectedFp[:]) {
		t.Errorf("fp mismatch")
	}

	// Receiver-side: parse wrap, run ECDH with recipient_sk, HKDF,
	// AES-GCM decrypt.
	ephPkCompressed := wrap[:33]
	nonce := wrap[33:45]
	ctWithTag := wrap[45:]

	ephPub, err := decodeP256CompressedToEcdh(ephPkCompressed)
	if err != nil {
		t.Fatalf("decode eph pubkey: %v", err)
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		t.Fatalf("recipient ECDH: %v", err)
	}

	info := append([]byte("NPVS-v1-wrap"), configID...)
	kdk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, fp, info), kdk); err != nil {
		t.Fatalf("HKDF: %v", err)
	}

	block, _ := aes.NewCipher(kdk)
	gcm, _ := cipher.NewGCM(block)
	recovered, err := gcm.Open(nil, nonce, ctWithTag, fp)
	if err != nil {
		t.Fatalf("recipient gcm open: %v", err)
	}
	if !bytes.Equal(recovered, dek) {
		t.Errorf("DEK mismatch — sender %x recovered %x", dek, recovered)
	}
}

func TestEcdhEphemeralWrapRejectsInvalidRecipientPubkey(t *testing.T) {
	// 33 bytes but with a prefix that's neither 0x02 nor 0x03.
	bad := make([]byte, 33)
	bad[0] = 0x05
	_, _, err := ecdhEphemeralWrap(bad, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0}, 32))
	if err == nil {
		t.Fatal("expected error for invalid pubkey")
	}
}

// ─── Full envelope round trip ─────────────────────────────────────

func TestMintEnvelopeRoundTrip(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	recipientPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipientPubCompressed, _ := compressUncompressedP256(recipientPriv.PublicKey().Bytes())

	out, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{recipientPubCompressed},
		IssuerURL:        "https://issuer.test/v1/issue",
		IssuedAt:         time.Date(2026, 5, 27, 18, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(out.EnvelopeBytes) < 200 {
		t.Errorf("envelope suspiciously small: %d bytes", len(out.EnvelopeBytes))
	}

	// Decode wire layout.
	dec, err := decodeEnvelopeWire(out.EnvelopeBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Header.V != 1 {
		t.Errorf("header.v = %d, want 1", dec.Header.V)
	}
	if dec.Header.IssuedAt == "" {
		t.Error("issuedAt empty")
	}
	if len(dec.Header.Recipients) != 1 {
		t.Fatalf("want 1 recipient, got %d", len(dec.Header.Recipients))
	}

	// Verify the signature over the canonical signed range.
	toSign := buildSignedRange(dec.HeaderBytes, dec.BodyNonce, dec.BodyCiphertext)
	hash := sha256.Sum256(toSign)
	if len(dec.Signature) != 64 {
		t.Fatalf("sig len = %d", len(dec.Signature))
	}
	// P1363 → r,s back to verify.
	r := new(big.Int).SetBytes(dec.Signature[:32])
	s := new(big.Int).SetBytes(dec.Signature[32:])
	if !ecdsa.Verify(&creatorPriv.PublicKey, hash[:], r, s) {
		t.Error("signature failed verification with creator pubkey")
	}

	// Unwrap the DEK as the recipient would.
	wrapBytes, err := b64url.DecodeString(dec.Header.Recipients[0].Wrap)
	if err != nil {
		t.Fatalf("decode wrap: %v", err)
	}
	ephPkCompressed := wrapBytes[:33]
	nonce := wrapBytes[33:45]
	ctWithTag := wrapBytes[45:]
	ephPub, _ := decodeP256CompressedToEcdh(ephPkCompressed)
	shared, _ := recipientPriv.ECDH(ephPub)
	fp := sha256.Sum256(recipientPubCompressed)
	configID, _ := b64url.DecodeString(dec.Header.ConfigID)
	info := append([]byte("NPVS-v1-wrap"), configID...)
	kdk := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, shared, fp[:], info), kdk)
	block, _ := aes.NewCipher(kdk)
	gcm, _ := cipher.NewGCM(block)
	dek, err := gcm.Open(nil, nonce, ctWithTag, fp[:])
	if err != nil {
		t.Fatalf("recipient unwrap: %v", err)
	}

	// Decrypt the body. AAD = headerBytes.
	body, err := chachaPoly1305Decrypt(dek, dec.BodyNonce, dec.HeaderBytes, dec.BodyCiphertext)
	if err != nil {
		t.Fatalf("body decrypt: %v", err)
	}

	// Parse the body and check fields.
	var b issuerBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if b.Kind != "v2-issuer" {
		t.Errorf("body.kind = %q, want v2-issuer", b.Kind)
	}
	if b.IssuerURL != "https://issuer.test/v1/issue" {
		t.Errorf("body.issuerUrl = %q", b.IssuerURL)
	}
	// creatorPubkey in the body matches header.creator.pk.
	if b.CreatorPubkey != dec.Header.Creator.Pk {
		t.Errorf("body.creatorPubkey != header.creator.pk")
	}

	// configFp is sha256 of the envelope bytes, base64url-no-pad.
	expectedConfigFp := sha256.Sum256(out.EnvelopeBytes)
	if out.ConfigFp != b64url.EncodeToString(expectedConfigFp[:]) {
		t.Errorf("configFp mismatch")
	}
}

func TestMintEnvelopeMultipleRecipients(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubs := make([][]byte, 3)
	for i := range pubs {
		p, _ := ecdh.P256().GenerateKey(rand.Reader)
		pubs[i], _ = compressUncompressedP256(p.PublicKey().Bytes())
	}
	out, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: pubs,
		IssuerURL:        "https://x.test/v1/issue",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	dec, _ := decodeEnvelopeWire(out.EnvelopeBytes)
	if len(dec.Header.Recipients) != 3 {
		t.Errorf("recipients = %d, want 3", len(dec.Header.Recipients))
	}
	// Each recipient's fp must be distinct.
	seen := map[string]bool{}
	for _, r := range dec.Header.Recipients {
		if seen[r.Fp] {
			t.Errorf("duplicate fp: %s", r.Fp)
		}
		seen[r.Fp] = true
	}
}

func TestMintEnvelopeRejectsEmptyRecipients(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: nil,
		IssuerURL:        "https://x.test/v1/issue",
	})
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Errorf("expected recipient-required error, got %v", err)
	}
}

func TestMintEnvelopeRejectsBadRecipientLength(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{make([]byte, 32)}, // should be 33
		IssuerURL:        "https://x.test/v1/issue",
	})
	if err == nil || !strings.Contains(err.Error(), "33") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestMintEnvelopeRejectsMissingIssuerURL(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	pc, _ := compressUncompressedP256(p.PublicKey().Bytes())
	_, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{pc},
	})
	if err == nil {
		t.Error("expected IssuerURL error")
	}
}

func TestSameInputsProduceDifferentEnvelopes(t *testing.T) {
	// DEK + body nonce are random per seal — re-running the minter
	// with identical inputs should produce different bytes (and thus
	// different configFps). Protects against accidental
	// determinism that would defeat replay resistance.
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	pc, _ := compressUncompressedP256(p.PublicKey().Bytes())
	configID := bytes.Repeat([]byte{0xCC}, 16)
	in := mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{pc},
		IssuerURL:        "https://x.test/v1/issue",
		ConfigID:         configID,
		IssuedAt:         time.Date(2026, 5, 27, 18, 0, 0, 0, time.UTC),
	}
	a, _ := mintIssuerEnvelope(in)
	b, _ := mintIssuerEnvelope(in)
	if bytes.Equal(a.EnvelopeBytes, b.EnvelopeBytes) {
		t.Error("two mint runs with same input produced identical bytes")
	}
	if a.ConfigFp == b.ConfigFp {
		t.Error("two mint runs produced same configFp")
	}
}
