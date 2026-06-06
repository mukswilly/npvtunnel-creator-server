package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// b64url is base64.URLEncoding with padding stripped — matches the
// client side's `Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)`.
var b64url = base64.URLEncoding.WithPadding(base64.NoPadding)

// decodeP256Compressed decodes a 33-byte SEC 1 compressed P-256 pubkey
// from base64url-no-pad to an *ecdsa.PublicKey suitable for
// ecdsa.Verify.
func decodeP256Compressed(b64 string) (*ecdsa.PublicKey, error) {
	raw, err := b64url.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("bad base64: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("want 33 bytes (P-256 compressed), got %d", len(raw))
	}
	curve := elliptic.P256()
	// nolint:staticcheck // SA1019: elliptic.UnmarshalCompressed remains the
	// only stdlib way to round-trip SEC 1 compressed form to (X,Y) coords
	// that ecdsa.Verify needs. crypto/ecdh has compressed-form support but
	// returns its own opaque key type that doesn't interop with ecdsa.
	x, y := elliptic.UnmarshalCompressed(curve, raw)
	if x == nil {
		return nil, errors.New("invalid compressed point (not on curve)")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// verifyP1363Signature checks an ECDSA-P256 P1363-format signature
// (raw 64 bytes: r || s, 32 bytes each, big-endian) against `msg`,
// hashing the message with SHA-256 first.
//
// Matches the client's signing which produces the
// same P1363 layout.
func verifyP1363Signature(pub *ecdsa.PublicKey, msg, signatureRaw []byte) bool {
	if len(signatureRaw) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(signatureRaw[:32])
	s := new(big.Int).SetBytes(signatureRaw[32:])
	hash := sha256.Sum256(msg)
	return ecdsa.Verify(pub, hash[:], r, s)
}

// ──────────────────────────────────────────────────────────────────
// Phase 3 issuance signing — must match the client's signing input
// ──────────────────────────────────────────────────────────────────

// issueRequestSigningInput reconstructs the bytes the recipient signed
// over to produce IssueRequest.RequestSignature. Must match the client
// helper `issueRequestSigningInput`.
//
// The "configId" position used to be a SHA-256(envelopeBytes) value
// labeled "configFp"; the field name changed when the
// routing key moved to envelope-header configId (see ConfigEntry kdoc
// in state.go). The signing-string layout — pipe-delimited fields in
// this order — is unchanged; only what goes in the slot is different.
//
// On the pipe delimiter (not length-prefixed): of the four fields,
// devicePk / configId / requestNonce are base64url-no-pad (alphabet
// [A-Za-z0-9_-], no '|'), and the attestation token is also base64url-
// no-pad (a length-prefixed DER chain on Android; empty otherwise). So
// no field can contain '|' in a well-formed request, and the boundaries
// are unambiguous in practice. Even a malicious client stuffing a '|'
// into the token gains nothing: the server routes and gates off the
// parsed JSON struct fields (req.ConfigID, etc.), never by re-splitting
// this signing string, and any signature still has to verify under the
// client's OWN devicePk. The string exists only to bind the signature.
// Length-prefixing would remove the ambiguity class entirely but is a
// breaking wire change (both sides must switch in lockstep with a
// protocol-version bump) — deliberately not done as a one-sided edit.
func issueRequestSigningInput(req *IssueRequest) []byte {
	return []byte("v1.issue|" + req.DevicePk + "|" + req.Attestation.Token + "|" + req.ConfigID + "|" + req.RequestNonce)
}

// verifyIssueRequestSignature checks IssueRequest.RequestSignature against
// IssueRequest.DevicePk.
func verifyIssueRequestSignature(req *IssueRequest) (bool, error) {
	devicePub, err := decodeP256Compressed(req.DevicePk)
	if err != nil {
		return false, fmt.Errorf("bad devicePk: %w", err)
	}
	sigRaw, err := b64url.DecodeString(req.RequestSignature)
	if err != nil {
		return false, fmt.Errorf("bad signature base64: %w", err)
	}
	return verifyP1363Signature(devicePub, issueRequestSigningInput(req), sigRaw), nil
}

// issueReceiptSigningInput reconstructs the bytes the issuer signs to
// produce IssueResponse.ReceiptSig. Must match the client helper
// `issueReceiptSigningInput`.
//
// Binds the issued credential to (a) the specific device, (b) the specific
// request that produced it (via the recipient-chosen requestNonce), and
// (c) the exact ConfigB64 returned. So a MITM issuer can't swap a
// different device's config into this response, and the recipient can't
// replay a stale receipt.
//
// The receipt covers ConfigB64 verbatim — recipients sign-verify before
// base64-decoding + parsing, which avoids any JSON canonicalization
// question (the bytes received are the bytes signed).
func issueReceiptSigningInput(devicePk, requestNonce string, resp *IssueResponse) []byte {
	return []byte("v1.receipt|" + devicePk + "|" + requestNonce + "|" + resp.ExpiresAt + "|" + resp.ConfigB64)
}

// signReceipt signs the canonical receipt input with the creator's signing
// key, producing the P1363-format 64-byte signature, base64url-no-pad
// encoded. The result is what goes in IssueResponse.ReceiptSig.
func signReceipt(creatorPriv *ecdsa.PrivateKey, devicePk, requestNonce string, resp *IssueResponse) (string, error) {
	msg := issueReceiptSigningInput(devicePk, requestNonce, resp)
	hash := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, creatorPriv, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa.Sign: %w", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// Left-pad to 32 bytes (big.Int.Bytes returns shortest-possible form).
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return b64url.EncodeToString(sig), nil
}
