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

// Cross-language envelope fixture.
//
// This test produces a committed `.json` fixture under
// creator-server/testdata/cross-lang-fixture.json the FIRST time it
// runs (or after the file is deleted), and on every subsequent run
// it parses the committed fixture through Go's own codec to confirm
// the bytes still round-trip cleanly.
//
// The fixture is the contract the NpvTunnel client's cross-language
// test reads.
// The client runs the same envelope through its production decoder
// (its decoder). If client's
// strict JSON deserializer or crypto primitives ever diverge from
// Go's, that test fails — closing the byte-exact cross-language
// gap that the Go-only round-trip can't reach.
//
// To re-roll the fixture after an intentional codec change:
//
//	rm creator-server/testdata/cross-lang-fixture.json
//	go test -run TestCrossLanguageFixtureValid ./creator-server/...
//
// Then commit the regenerated file. Reviewers see the diff and
// know the format changed deliberately.

const crossLangFixturePath = "testdata/cross-lang-fixture.json"

// crossLangFixture is the wire shape of the committed fixture. All
// bytes are base64url-no-pad.
type crossLangFixture struct {
	Comment string `json:"_comment"`

	// Envelope is the raw .npvs bytes a client recipient would
	// receive on the wire.
	Envelope string `json:"envelopeB64"`

	// RecipientPrivKeyD is the recipient's P-256 private scalar
	// (32 bytes). client reconstitutes a JCA ECPrivateKey from
	// this and runs the §6.5 receiver step.
	RecipientPrivKeyD string `json:"recipientPrivKeyDB64"`

	// RecipientPubKeyCompressed is the SEC1 compressed pubkey
	// corresponding to RecipientPrivKeyD (33 bytes). Provided so
	// the client test can sanity-check its reconstruction matches.
	RecipientPubKeyCompressed string `json:"recipientPubKeyCompressedB64"`

	// CreatorPubKeyCompressed is the creator's signing pubkey
	// (33 bytes). client verifies the envelope's signature against
	// this — the client codec also extracts it from the header
	// itself; this field is for the test to cross-check.
	CreatorPubKeyCompressed string `json:"creatorPubKeyCompressedB64"`

	// ConfigFp is base64url-no-pad of SHA-256(envelopeBytes).
	ConfigFp string `json:"configFp"`

	// ConfigId is the 16-byte stable identifier embedded in the
	// header.
	ConfigId string `json:"configId"`

	// Expected captures the post-unseal values the client test
	// should assert against.
	Expected crossLangExpected `json:"expected"`
}

type crossLangExpected struct {
	Kind            string `json:"kind"`
	IssuerURL       string `json:"issuerUrl"`
	VpnProtocolHint string `json:"vpnProtocolHint"`
	// CreatorPubkeyB64 inside the body must equal the header's
	// creator.pk field (the V2 body redundantly carries this so the
	// recipient can verify receipts later without keeping the
	// envelope header in memory).
	CreatorPubkeyB64 string `json:"creatorPubkeyB64"`
}

// TestCrossLanguageFixtureValid loads (or generates) the fixture,
// then runs it back through the Go side as a sanity check that the
// committed bytes haven't bit-rotted or been corrupted.
func TestCrossLanguageFixtureValid(t *testing.T) {
	fx, err := loadOrGenerateCrossLangFixture(t)
	if err != nil {
		t.Fatalf("load/generate fixture: %v", err)
	}

	envelopeBytes, err := b64url.DecodeString(fx.Envelope)
	if err != nil {
		t.Fatalf("decode envelope b64: %v", err)
	}

	// Decode wire layout.
	dec, err := decodeEnvelopeWire(envelopeBytes)
	if err != nil {
		t.Fatalf("decode envelope wire: %v", err)
	}

	// Verify configFp matches sha256 of the envelope bytes (paranoia
	// check on the fixture).
	gotFp := sha256.Sum256(envelopeBytes)
	if b64url.EncodeToString(gotFp[:]) != fx.ConfigFp {
		t.Errorf("fixture configFp doesn't match SHA-256(envelope)")
	}

	// Run the §6.5 receiver step with the fixture's recipient privkey.
	recipientPrivD, err := b64url.DecodeString(fx.RecipientPrivKeyD)
	if err != nil {
		t.Fatalf("decode privkey D: %v", err)
	}
	dek, err := unwrapDekWithSoftwarePriv(dec, recipientPrivD)
	if err != nil {
		t.Fatalf("unwrap DEK with fixture privkey: %v", err)
	}

	// Decrypt the body.
	body, err := chachaPoly1305Decrypt(dek, dec.BodyNonce, dec.HeaderBytes, dec.BodyCiphertext)
	if err != nil {
		t.Fatalf("body decrypt: %v", err)
	}

	// Parse the issuer body and assert expected fields.
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
	if b.VpnProtocolHint == nil || *b.VpnProtocolHint != fx.Expected.VpnProtocolHint {
		t.Errorf("body.vpnProtocolHint = %v, want %q", b.VpnProtocolHint, fx.Expected.VpnProtocolHint)
	}
	if b.CreatorPubkey != fx.Expected.CreatorPubkeyB64 {
		t.Errorf("body.creatorPubkey = %q, want %q", b.CreatorPubkey, fx.Expected.CreatorPubkeyB64)
	}

	// Verify the header's creator.pk matches the fixture's creator
	// pubkey field (the client codec uses header.creator.pk to verify
	// the ECDSA signature; both must agree for cross-language tests
	// to be meaningful).
	if dec.Header.Creator.Pk != fx.CreatorPubKeyCompressed {
		t.Errorf("header.creator.pk = %q, fixture creator = %q",
			dec.Header.Creator.Pk, fx.CreatorPubKeyCompressed)
	}
}

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
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// File missing → regenerate. This is the deliberate re-roll
	// path. Reviewer will see the new file in `git status` and
	// either commit it (intentional re-roll) or restore the old
	// one (accidental delete).
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

func generateCrossLangFixture() (*crossLangFixture, error) {
	// Generate a recipient keypair. We capture both the raw 32-byte
	// scalar D and the SEC1 compressed pubkey, so the client test
	// can reconstitute both sides.
	recipientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	recipientPub := recipientPriv.PublicKey().Bytes() // 65-byte uncompressed
	recipientPubCompressed, err := compressUncompressedP256(recipientPub)
	if err != nil {
		return nil, err
	}

	// Generate a creator signing keypair. (For this fixture we don't
	// reuse a persisted creator-key.pem because the fixture should
	// be self-contained and re-rollable from any dev machine.)
	creatorPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	creatorPubCompressed, err := compressP256(&creatorPriv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Mint an envelope addressed to the recipient.
	const (
		issuerURL       = "https://issuer.test/v1/issue"
		vpnProtocolHint = "xray-vless-reality"
	)
	out, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorPriv,
		RecipientPubKeys: [][]byte{recipientPubCompressed},
		IssuerURL:        issuerURL,
		VpnProtocolHint:  vpnProtocolHint,
		// Frozen timestamp so the fixture's issuedAt is human-
		// readable. Doesn't affect cryptographic correctness.
		IssuedAt: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		return nil, err
	}

	return &crossLangFixture{
		Comment: "Cross-language envelope fixture. Generated by " +
			"creator-server/cross_language_fixture_test.go's " +
			"TestCrossLanguageFixtureValid. Read by both that Go test " +
			"and the NpvTunnel client's cross-language test. Re-roll by " +
			"deleting this file and re-running either test.",
		Envelope:                  b64url.EncodeToString(out.EnvelopeBytes),
		RecipientPrivKeyD:         b64url.EncodeToString(recipientPriv.Bytes()),
		RecipientPubKeyCompressed: b64url.EncodeToString(recipientPubCompressed),
		CreatorPubKeyCompressed:   b64url.EncodeToString(creatorPubCompressed),
		ConfigFp:                  out.ConfigFp,
		ConfigId:                  b64url.EncodeToString(out.ConfigID),
		Expected: crossLangExpected{
			Kind:             "v2-issuer",
			IssuerURL:        issuerURL,
			VpnProtocolHint:  vpnProtocolHint,
			CreatorPubkeyB64: b64url.EncodeToString(creatorPubCompressed),
		},
	}, nil
}

// unwrapDekWithSoftwarePriv runs the §6.5 RECEIVER step in pure Go
// using a software-loaded recipient private key (raw 32-byte
// scalar). This is what the client's software-identity test
// shim does in JVM-land — keeping a Go-side implementation here
// lets the Go fixture test self-validate without needing the
// production the client (which only works on a real
// Android keystore).
func unwrapDekWithSoftwarePriv(env *envelopeDecoded, recipientPrivD []byte) ([]byte, error) {
	// Locate the wrap for this recipient. The fixture has exactly
	// one recipient by construction, so we don't need fingerprint
	// matching here.
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

	// Reconstitute ECDH private key from scalar.
	recipientPriv, err := ecdh.P256().NewPrivateKey(recipientPrivD)
	if err != nil {
		return nil, err
	}

	// Derive the recipient's fingerprint (matches what the sender
	// used as HKDF salt + GCM AAD).
	recipientPubBytes := recipientPriv.PublicKey().Bytes()
	recipientPubCompressed, err := compressUncompressedP256(recipientPubBytes)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(recipientPubCompressed)

	// Decompose wrap into its fields.
	ephPkCompressed := wrap[:33]
	nonce := wrap[33:45]
	ctWithTag := wrap[45:]

	// ECDH(my_sk, eph_pk) → shared X.
	ephPub, err := decodeP256CompressedToEcdh(ephPkCompressed)
	if err != nil {
		return nil, err
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	defer zeroize(shared)

	// HKDF.
	info := append([]byte("NPVS-v1-wrap"), configID...)
	kdk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, fp[:], info), kdk); err != nil {
		return nil, err
	}
	defer zeroize(kdk)

	// AES-GCM decrypt the DEK.
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
