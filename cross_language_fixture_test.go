package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// crossLangFixturePath is the committed shared fixture that pins the byte-exact wire format
// (canonical-JSON header and envelope layout) so independent implementations stay in agreement.
// This file must not be weakened or deleted; re-roll only by deleting it and re-running the test.
const crossLangFixturePath = "testdata/cross-lang-fixture.json"

// crossLangFixture describes the JSON shape of the committed cross-language fixture: a sample
// envelope plus the recipient/creator key material and expected decrypted values needed to
// verify any implementation decodes and decrypts the canonical wire bytes identically.
type crossLangFixture struct {
	Comment string `json:"_comment"`

	Envelope string `json:"envelopeB64"`

	RecipientPrivKeyD string `json:"recipientPrivKeyDB64"`

	RecipientPubKeyCompressed string `json:"recipientPubKeyCompressedB64"`

	CreatorPubKeyCompressed string `json:"creatorPubKeyCompressedB64"`

	ConfigFp string `json:"configFp"`

	ConfigId string `json:"configId"`

	Expected crossLangExpected `json:"expected"`
}

// crossLangExpected holds the body fields any conformant decoder must recover from the fixture envelope.
type crossLangExpected struct {
	Kind      string `json:"kind"`
	IssuerURL string `json:"issuerUrl"`

	CreatorPubkeyB64 string `json:"creatorPubkeyB64"`
}

// TestCrossLanguageFixtureValid is the conformance guard for the wire format: it decodes the
// shared committed fixture, checks configFp = SHA-256(envelope), unwraps the DEK with the
// fixture's recipient key, decrypts the body, and asserts the recovered fields exactly match
// the fixture's expected values. This pins the byte-exact canonical-JSON serialization so any
// independent implementation that reads the same fixture agrees byte-for-byte. The fixture and
// this test must not be weakened or deleted.
func TestCrossLanguageFixtureValid(t *testing.T) {
	fx, err := loadOrGenerateCrossLangFixture(t)
	if err != nil {
		t.Fatalf("load/generate fixture: %v", err)
	}

	envelopeBytes, err := b64url.DecodeString(fx.Envelope)
	if err != nil {
		t.Fatalf("decode envelope b64: %v", err)
	}

	dec, err := decodeEnvelopeWire(envelopeBytes)
	if err != nil {
		t.Fatalf("decode envelope wire: %v", err)
	}

	gotFp := sha256.Sum256(envelopeBytes)
	if b64url.EncodeToString(gotFp[:]) != fx.ConfigFp {
		t.Errorf("fixture configFp doesn't match SHA-256(envelope)")
	}

	recipientPrivD, err := b64url.DecodeString(fx.RecipientPrivKeyD)
	if err != nil {
		t.Fatalf("decode privkey D: %v", err)
	}
	dek, err := unwrapDekWithSoftwarePriv(dec, recipientPrivD)
	if err != nil {
		t.Fatalf("unwrap DEK with fixture privkey: %v", err)
	}

	body, err := chachaPoly1305Decrypt(dek, dec.BodyNonce, dec.HeaderBytes, dec.BodyCiphertext)
	if err != nil {
		t.Fatalf("body decrypt: %v", err)
	}

	var b issuerBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("parse issuer body: %v", err)
	}
	if b.Kind != fx.Expected.Kind {
		t.Errorf("body.kind = %q, want %q", b.Kind, fx.Expected.Kind)
	}
	if b.IssuerURL != fx.Expected.IssuerURL {
		t.Errorf("body.issuerUrl = %q, want %q", b.IssuerURL, fx.Expected.IssuerURL)
	}
	if b.CreatorPubkey != fx.Expected.CreatorPubkeyB64 {
		t.Errorf("body.creatorPubkey = %q, want %q", b.CreatorPubkey, fx.Expected.CreatorPubkeyB64)
	}

	if dec.Header.Creator.Pk != fx.CreatorPubKeyCompressed {
		t.Errorf("header.creator.pk = %q, fixture creator = %q",
			dec.Header.Creator.Pk, fx.CreatorPubKeyCompressed)
	}
}

// loadOrGenerateCrossLangFixture reads the committed fixture, or generates and writes a fresh
// one if it is missing so a first run is self-bootstrapping; a freshly generated fixture must be
// reviewed and committed to lock in the wire bytes that other implementations validate against.
func loadOrGenerateCrossLangFixture(t *testing.T) (*crossLangFixture, error) {
	t.Helper()
	data, err := os.ReadFile(crossLangFixturePath)
	if err == nil {
		var fx crossLangFixture
		if err := json.Unmarshal(data, &fx); err != nil {
			return nil, err
		}
		return &fx, nil
	}
	// Only a missing file triggers regeneration; any other read error is fatal.
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	t.Logf("cross-lang fixture missing at %s — regenerating from scratch", crossLangFixturePath)

	fx, err := generateCrossLangFixture()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(crossLangFixturePath), 0o755); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(crossLangFixturePath, out, 0o644); err != nil {
		return nil, err
	}
	t.Logf("wrote fresh fixture (%d bytes) — commit it if intentional", len(out))
	return fx, nil
}

// generateCrossLangFixture mints a sample envelope with fresh recipient and creator keys and
// packages everything (envelope, keys, configFp/configId, expected body) needed to validate the
// wire format. The issuedAt is fixed so the generated fixture is stable across runs.
func generateCrossLangFixture() (*crossLangFixture, error) {

	recipientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	recipientPub := recipientPriv.PublicKey().Bytes()
	recipientPubCompressed, err := compressUncompressedP256(recipientPub)
	if err != nil {
		return nil, err
	}

	creatorPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	creatorPubCompressed, err := compressP256(&creatorPriv.PublicKey)
	if err != nil {
		return nil, err
	}

	const issuerURL = "https://issuer.test/v1/issue"
	out, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{recipientPubCompressed},
		IssuerURL:        issuerURL,

		IssuedAt: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		return nil, err
	}

	return &crossLangFixture{
		Comment: "Cross-language envelope fixture generated by " +
			"creator-server/cross_language_fixture_test.go. Read by " +
			"this Go test and recipient cross-language conformance tests. " +
			"Re-roll by deleting this file and re-running the test.",
		Envelope:                  b64url.EncodeToString(out.EnvelopeBytes),
		RecipientPrivKeyD:         b64url.EncodeToString(recipientPriv.Bytes()),
		RecipientPubKeyCompressed: b64url.EncodeToString(recipientPubCompressed),
		CreatorPubKeyCompressed:   b64url.EncodeToString(creatorPubCompressed),
		ConfigFp:                  out.ConfigFp,
		ConfigId:                  b64url.EncodeToString(out.ConfigID),
		Expected: crossLangExpected{
			Kind:             "v2-issuer",
			IssuerURL:        issuerURL,
			CreatorPubkeyB64: b64url.EncodeToString(creatorPubCompressed),
		},
	}, nil
}

// unwrapDekWithSoftwarePriv recovers the DEK from a single-recipient envelope given the
// recipient private scalar, performing the recipient side of the wrap: ECDH against the
// ephemeral pubkey, HKDF (salted by recipient fingerprint, bound to configID) to the KDK, then
// AES-GCM open. It is the reference unwrap an independent implementation must reproduce.
func unwrapDekWithSoftwarePriv(env *envelopeDecoded, recipientPrivD []byte) ([]byte, error) {

	if len(env.Header.Recipients) != 1 {
		return nil, errors.New("fixture must have exactly 1 recipient")
	}
	wrap, err := b64url.DecodeString(env.Header.Recipients[0].Wrap)
	if err != nil {
		return nil, err
	}
	if len(wrap) != envelopeWrapLen {
		return nil, errors.New("wrap is not 93 bytes")
	}
	configID, err := b64url.DecodeString(env.Header.ConfigID)
	if err != nil {
		return nil, err
	}

	recipientPriv, err := ecdh.P256().NewPrivateKey(recipientPrivD)
	if err != nil {
		return nil, err
	}

	recipientPubBytes := recipientPriv.PublicKey().Bytes()
	recipientPubCompressed, err := compressUncompressedP256(recipientPubBytes)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(recipientPubCompressed)

	// Wrap layout: 33-byte ephemeral compressed pubkey, 12-byte nonce, then ciphertext+tag.
	ephPkCompressed := wrap[:33]
	nonce := wrap[33:45]
	ctWithTag := wrap[45:]

	ephPub, err := decodeP256CompressedToEcdh(ephPkCompressed)
	if err != nil {
		return nil, err
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	defer zeroize(shared)

	info := append([]byte("NPVS-v1-wrap"), configID...)
	kdk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, fp[:], info), kdk); err != nil {
		return nil, err
	}
	defer zeroize(kdk)

	block, err := aes.NewCipher(kdk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ctWithTag, fp[:])
}
