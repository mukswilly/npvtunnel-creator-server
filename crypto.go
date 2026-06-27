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

// b64url is the base64url alphabet without padding, used for every base64 field
// on the wire (public keys, signatures, config payloads).
var b64url = base64.URLEncoding.WithPadding(base64.NoPadding)

// decodeP256Compressed decodes a base64url, 33-byte SEC1-compressed P-256
// public key into an *ecdsa.PublicKey, rejecting points not on the curve.
func decodeP256Compressed(b64 string) (*ecdsa.PublicKey, error) {
	raw, err := b64url.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("bad base64: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("want 33 bytes (P-256 compressed), got %d", len(raw))
	}
	curve := elliptic.P256()

	x, y := elliptic.UnmarshalCompressed(curve, raw)
	if x == nil {
		return nil, errors.New("invalid compressed point (not on curve)")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// verifyP1363Signature verifies an ECDSA-P256 signature over SHA-256(msg). The
// signature is the fixed 64-byte P1363 form: r||s, 32 bytes each, big-endian.
func verifyP1363Signature(pub *ecdsa.PublicKey, msg, signatureRaw []byte) bool {
	if len(signatureRaw) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(signatureRaw[:32])
	s := new(big.Int).SetBytes(signatureRaw[32:])
	hash := sha256.Sum256(msg)
	return ecdsa.Verify(pub, hash[:], r, s)
}

// issueRequestSigningInput is the exact byte string an issue request is signed
// over. The pipe-delimited layout is fixed by the protocol; changing any field,
// order, or separator invalidates every client signature.
func issueRequestSigningInput(req *IssueRequest) []byte {
	return []byte("v1.issue|" + req.DevicePk + "|" + req.Attestation.Token + "|" + req.ConfigID + "|" + req.RequestNonce)
}

// verifyIssueRequestSignature checks that RequestSignature was produced by the
// DevicePk key over issueRequestSigningInput. A returned error means the
// request was malformed (unparseable key or signature); (false, nil) means a
// well-formed signature that did not verify.
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

// issueReceiptSigningInput is the exact byte string the response receipt is
// signed over. Like the request input, its layout is fixed by the protocol.
func issueReceiptSigningInput(devicePk, requestNonce string, resp *IssueResponse) []byte {
	return []byte("v1.receipt|" + devicePk + "|" + requestNonce + "|" + resp.ExpiresAt + "|" + resp.ConfigB64)
}

// signReceipt signs the receipt input with the creator key and returns the
// base64url P1363 signature placed in IssueResponse.ReceiptSig.
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

	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return b64url.EncodeToString(sig), nil
}
