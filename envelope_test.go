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

// TestCanonicalJSONSortsKeys verifies object keys are emitted in lexicographic order.
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

// TestCanonicalJSONNestedSorting verifies keys are sorted recursively through nested objects and arrays.
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

// TestCanonicalJSONEscapesControlChars verifies control characters and quotes are escaped to the canonical form.
func TestCanonicalJSONEscapesControlChars(t *testing.T) {
	in := map[string]any{"k": "a\nb\tc\"d\\e\x01f"}
	out, _ := canonicalJSON(in)

	want := "{\"k\":\"a\\nb\\tc\\\"d\\\\e\\u0001f\"}"
	if string(out) != want {
		t.Errorf("got %s\nwant %s", out, want)
	}
}

// TestCanonicalJSONFromTypedStructPreservesIntegers verifies struct encoding sorts keys, emits null for nil pointers, and keeps integers integral.
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

	want := `{"id":"abc","policy":{"expiresAt":null,"onlyMobileNetwork":true},"v":1}`
	if string(out) != want {
		t.Errorf("got %s\nwant %s", out, want)
	}
}

// TestCompressDecompressRoundTrip verifies a P-256 public key compresses to 33 bytes with a valid 0x02/0x03 prefix and decompresses back.
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

	if _, err := decodeP256CompressedToEcdh(compressed); err != nil {
		t.Errorf("decompress failed: %v", err)
	}
}

// TestEcdhEphemeralWrapRoundTrip verifies the 93-byte DEK wrap (ephemeral pubkey + nonce + ciphertext) and that the recipient recovers the DEK via ECDH+HKDF+AES-GCM bound to the recipient fingerprint and configID.
func TestEcdhEphemeralWrapRoundTrip(t *testing.T) {
	recipientPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey().Bytes()
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

	// Wrap layout: 33-byte ephemeral compressed pubkey, 12-byte nonce, then ciphertext+tag.
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

	// Derive the key-derivation key: HKDF over the ECDH shared secret, salted with the
	// recipient fingerprint and bound to the configID via the info string.
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

// TestEcdhEphemeralWrapRejectsInvalidRecipientPubkey verifies wrapping fails when the recipient pubkey has an invalid compression prefix.
func TestEcdhEphemeralWrapRejectsInvalidRecipientPubkey(t *testing.T) {

	bad := make([]byte, 33)
	bad[0] = 0x05 // not a valid compressed-point prefix (must be 0x02 or 0x03)
	_, _, err := ecdhEphemeralWrap(bad, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0}, 32))
	if err == nil {
		t.Fatal("expected error for invalid pubkey")
	}
}

// TestMintEnvelopeRoundTrip mints an envelope, then exercises the full recipient path:
// decode the wire format, verify the creator signature over the signed range, unwrap the
// DEK, decrypt the body, and confirm the body fields and the configFp = SHA-256(envelope).
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

	// Signature covers header bytes + body nonce + body ciphertext, as a raw 64-byte r||s pair.
	toSign := buildSignedRange(dec.HeaderBytes, dec.BodyNonce, dec.BodyCiphertext)
	hash := sha256.Sum256(toSign)
	if len(dec.Signature) != 64 {
		t.Fatalf("sig len = %d", len(dec.Signature))
	}

	r := new(big.Int).SetBytes(dec.Signature[:32])
	s := new(big.Int).SetBytes(dec.Signature[32:])
	if !ecdsa.Verify(&creatorPriv.PublicKey, hash[:], r, s) {
		t.Error("signature failed verification with creator pubkey")
	}

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

	body, err := chachaPoly1305Decrypt(dek, dec.BodyNonce, dec.HeaderBytes, dec.BodyCiphertext)
	if err != nil {
		t.Fatalf("body decrypt: %v", err)
	}

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

	if b.CreatorPubkey != dec.Header.Creator.Pk {
		t.Errorf("body.creatorPubkey != header.creator.pk")
	}

	expectedConfigFp := sha256.Sum256(out.EnvelopeBytes)
	if out.ConfigFp != b64url.EncodeToString(expectedConfigFp[:]) {
		t.Errorf("configFp mismatch")
	}
}

// TestMintEnvelopeMultipleRecipients verifies one envelope carries a wrap per recipient, each with a distinct fingerprint.
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

	seen := map[string]bool{}
	for _, r := range dec.Header.Recipients {
		if seen[r.Fp] {
			t.Errorf("duplicate fp: %s", r.Fp)
		}
		seen[r.Fp] = true
	}
}

// TestMintEnvelopeRejectsEmptyRecipients verifies minting requires at least one recipient.
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

// TestMintEnvelopeRejectsBadRecipientLength verifies a recipient pubkey that isn't 33 bytes is rejected.
func TestMintEnvelopeRejectsBadRecipientLength(t *testing.T) {
	creatorPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{make([]byte, 32)},
		IssuerURL:        "https://x.test/v1/issue",
	})
	if err == nil || !strings.Contains(err.Error(), "33") {
		t.Errorf("expected length error, got %v", err)
	}
}

// TestMintEnvelopeRejectsMissingIssuerURL verifies minting requires an issuer URL.
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

// TestSameInputsProduceDifferentEnvelopes verifies minting is non-deterministic: identical
// inputs yield distinct envelope bytes and configFp, since fresh randomness (DEK, nonces,
// ephemeral keys) is drawn each time.
func TestSameInputsProduceDifferentEnvelopes(t *testing.T) {

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
