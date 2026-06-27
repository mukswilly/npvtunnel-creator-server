package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The .npvs envelope: a signed, encrypted container for a config payload,
// readable only by the recipients it is minted for. On-the-wire layout is a
// fixed binary frame:
//
//	"NPVS" magic (4) | version (1) | headerLen (4, big-endian) |
//	header (canonical JSON) | bodyNonce (12) | bodyLen (4, big-endian) |
//	body ciphertext | signature (64)
//
// The header is canonical JSON and is authenticated twice: it is the ECDSA
// signature input (with the rest of the frame) and the AEAD associated data for
// the body. The body is the config payload encrypted under a random DEK; the
// DEK is wrapped separately to each recipient. Every byte field is fixed-width,
// so these lengths are part of the wire contract.
const (
	envelopeMagicLen     = 4
	envelopeVersion      = 1
	envelopeVersionLen   = 1
	envelopeHeaderLenLen = 4
	envelopeBodyNonceLen = 12
	envelopeBodyLenLen   = 4
	envelopeSignatureLen = 64
	envelopeDEKLen       = 32
	envelopeConfigIDLen  = 16
	envelopeWrapLen      = 93
	envelopeP256CompLen  = 33
)

// envelopeMagic is the leading "NPVS" magic bytes.
var envelopeMagic = []byte{0x4E, 0x50, 0x56, 0x53}

// envelopeWrapInfoLabel is the fixed HKDF info prefix for per-recipient DEK
// wrapping; the configId is appended to it (see ecdhEphemeralWrap).
var envelopeWrapInfoLabel = []byte("NPVS-v1-wrap")

// envelopeHeader is the canonical-JSON header. Field names and ordering of the
// serialized form are fixed by canonical JSON (sorted keys).
type envelopeHeader struct {
	V          int                 `json:"v"`
	ConfigID   string              `json:"configId"`
	IssuedAt   string              `json:"issuedAt"`
	Creator    envelopeCreatorRef  `json:"creator"`
	Policy     envelopePolicy      `json:"policy"`
	Recipients []envelopeRecipient `json:"recipients"`
}

// envelopeCreatorRef identifies the signing creator: Fp is the SHA-256
// fingerprint of the compressed pubkey, Pk is the compressed pubkey itself.
type envelopeCreatorRef struct {
	Fp string `json:"fp"`
	Pk string `json:"pk"`
}

// envelopePolicy carries recipient-facing usage restrictions stamped into the
// envelope. ExpiresAt is a pointer so it serializes as null when unset.
type envelopePolicy struct {
	OnlyMobileNetwork   bool    `json:"onlyMobileNetwork"`
	AttestationLevel    string  `json:"attestationLevel"`
	ExpiresAt           *string `json:"expiresAt"`
	DisplayMessage      string  `json:"displayMessage"`
	CustomServerMessage string  `json:"customServerMessage"`
}

// envelopeRecipient is one per-recipient DEK wrap: Fp is the SHA-256
// fingerprint of the recipient's compressed pubkey, Wrap is the wrapped DEK.
type envelopeRecipient struct {
	Fp   string `json:"fp"`
	Wrap string `json:"wrap"`
}

// issuerBody is the plaintext body for the "v2-issuer" kind: instead of the
// config itself, it tells the recipient which issuer to call and which creator
// key to expect, so the config is fetched over /v1/issue.
type issuerBody struct {
	Kind          string `json:"kind"`
	CreatorPubkey string `json:"creatorPubkey"`
	IssuerURL     string `json:"issuerUrl"`
}

const issuerBodyKindV2 = "v2-issuer"

func encodeIssuerBody(b issuerBody) ([]byte, error) {

	return json.Marshal(b)
}

// mintInput is the set of parameters for minting one envelope.
type mintInput struct {
	CreatorKey *ecdsa.PrivateKey

	RecipientPubKeys [][]byte

	IssuerURL string

	ConfigID []byte

	IssuedAt time.Time

	Policy *envelopePolicy
}

// mintResult is a freshly minted envelope plus identifiers derived from it.
type mintResult struct {
	EnvelopeBytes []byte

	ConfigFp string

	ConfigID []byte
}

// mintIssuerEnvelope builds a "v2-issuer" envelope: it generates a random DEK,
// encrypts the issuer body under it, wraps the DEK to each recipient, then
// canonicalizes and signs the whole frame. At least one recipient is required;
// mass-share is intentionally unsupported.
func mintIssuerEnvelope(in mintInput) (*mintResult, error) {
	if in.CreatorKey == nil {
		return nil, fmt.Errorf("CreatorKey is required")
	}
	if len(in.RecipientPubKeys) == 0 {
		return nil, fmt.Errorf("at least one recipient pubkey is required (mass-share is intentionally not supported)")
	}
	for i, pk := range in.RecipientPubKeys {
		if len(pk) != envelopeP256CompLen {
			return nil, fmt.Errorf("recipient %d: pubkey must be %d bytes (P-256 compressed), got %d",
				i, envelopeP256CompLen, len(pk))
		}
	}
	if in.IssuerURL == "" {
		return nil, fmt.Errorf("IssuerURL is required")
	}

	configID := in.ConfigID
	if configID == nil {
		configID = make([]byte, envelopeConfigIDLen)
		if _, err := rand.Read(configID); err != nil {
			return nil, fmt.Errorf("generate configId: %w", err)
		}
	}
	if len(configID) != envelopeConfigIDLen {
		return nil, fmt.Errorf("ConfigID must be %d bytes, got %d", envelopeConfigIDLen, len(configID))
	}

	issuedAt := in.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	issuedAtStr := issuedAt.UTC().Format("2006-01-02T15:04:05.999999999Z")

	pol := in.Policy
	if pol == nil {
		pol = &envelopePolicy{
			OnlyMobileNetwork:   false,
			AttestationLevel:    "NONE",
			ExpiresAt:           nil,
			DisplayMessage:      "",
			CustomServerMessage: "",
		}
	}

	creatorPub, err := compressP256(&in.CreatorKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("compress creator pubkey: %w", err)
	}
	creatorFp := sha256.Sum256(creatorPub)

	dek := make([]byte, envelopeDEKLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	bodyNonce := make([]byte, envelopeBodyNonceLen)
	if _, err := rand.Read(bodyNonce); err != nil {
		return nil, fmt.Errorf("generate body nonce: %w", err)
	}

	recipientEntries := make([]envelopeRecipient, 0, len(in.RecipientPubKeys))
	for i, pk := range in.RecipientPubKeys {
		wrap, fp, err := ecdhEphemeralWrap(pk, configID, dek)
		if err != nil {
			return nil, fmt.Errorf("wrap recipient %d: %w", i, err)
		}
		recipientEntries = append(recipientEntries, envelopeRecipient{
			Fp:   b64url.EncodeToString(fp),
			Wrap: b64url.EncodeToString(wrap),
		})
	}

	header := envelopeHeader{
		V:        envelopeVersion,
		ConfigID: b64url.EncodeToString(configID),
		IssuedAt: issuedAtStr,
		Creator: envelopeCreatorRef{
			Fp: b64url.EncodeToString(creatorFp[:]),
			Pk: b64url.EncodeToString(creatorPub),
		},
		Policy:     *pol,
		Recipients: recipientEntries,
	}
	headerBytes, err := canonicalJSONOfStruct(header)
	if err != nil {
		return nil, fmt.Errorf("canonicalize header: %w", err)
	}

	bodyBytes, err := encodeIssuerBody(issuerBody{
		Kind:          issuerBodyKindV2,
		CreatorPubkey: b64url.EncodeToString(creatorPub),
		IssuerURL:     in.IssuerURL,
	})
	if err != nil {
		return nil, fmt.Errorf("encode issuer body: %w", err)
	}

	// The canonical header is the AEAD associated data, binding the encrypted
	// body to the exact header it was minted with.
	bodyCipher, err := chachaPoly1305Encrypt(dek, bodyNonce, headerBytes, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	toSign := buildSignedRange(headerBytes, bodyNonce, bodyCipher)
	sig, err := signP1363(in.CreatorKey, toSign)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	envelopeBytes := encodeEnvelopeWire(headerBytes, bodyNonce, bodyCipher, sig)
	configFp := sha256.Sum256(envelopeBytes)

	return &mintResult{
		EnvelopeBytes: envelopeBytes,
		ConfigFp:      b64url.EncodeToString(configFp[:]),
		ConfigID:      configID,
	}, nil
}

// encodeEnvelopeWire serializes the full frame including the trailing signature.
func encodeEnvelopeWire(headerBytes, bodyNonce, bodyCipher, signature []byte) []byte {
	total := envelopeMagicLen + envelopeVersionLen + envelopeHeaderLenLen +
		len(headerBytes) + envelopeBodyNonceLen + envelopeBodyLenLen +
		len(bodyCipher) + envelopeSignatureLen
	out := make([]byte, total)
	off := 0
	copy(out[off:], envelopeMagic)
	off += envelopeMagicLen
	out[off] = envelopeVersion
	off += envelopeVersionLen
	binary.BigEndian.PutUint32(out[off:], uint32(len(headerBytes)))
	off += envelopeHeaderLenLen
	copy(out[off:], headerBytes)
	off += len(headerBytes)
	copy(out[off:], bodyNonce)
	off += envelopeBodyNonceLen
	binary.BigEndian.PutUint32(out[off:], uint32(len(bodyCipher)))
	off += envelopeBodyLenLen
	copy(out[off:], bodyCipher)
	off += len(bodyCipher)
	copy(out[off:], signature)
	return out
}

// buildSignedRange returns the bytes covered by the signature: the whole frame
// up to but not including the signature itself.
func buildSignedRange(headerBytes, bodyNonce, bodyCipher []byte) []byte {
	total := envelopeMagicLen + envelopeVersionLen + envelopeHeaderLenLen +
		len(headerBytes) + envelopeBodyNonceLen + envelopeBodyLenLen + len(bodyCipher)
	buf := make([]byte, total)
	off := 0
	copy(buf[off:], envelopeMagic)
	off += envelopeMagicLen
	buf[off] = envelopeVersion
	off += envelopeVersionLen
	binary.BigEndian.PutUint32(buf[off:], uint32(len(headerBytes)))
	off += envelopeHeaderLenLen
	copy(buf[off:], headerBytes)
	off += len(headerBytes)
	copy(buf[off:], bodyNonce)
	off += envelopeBodyNonceLen
	binary.BigEndian.PutUint32(buf[off:], uint32(len(bodyCipher)))
	off += envelopeBodyLenLen
	copy(buf[off:], bodyCipher)
	return buf
}

// ecdhEphemeralWrap wraps dek for one recipient. It does an ephemeral-static
// ECDH against the recipient's P-256 key, derives a key-encryption key with
// HKDF-SHA256 (salt = recipient fingerprint, info = label || configId), then
// seals the DEK with AES-256-GCM (associated data = fingerprint). The 93-byte
// wrap is ephemeralPub(33) || gcmNonce(12) || ciphertext+tag(48). It returns
// the wrap and the recipient fingerprint.
func ecdhEphemeralWrap(recipientPubCompressed, configID, dek []byte) ([]byte, []byte, error) {
	curve := ecdh.P256()

	recipientPub, err := decodeP256CompressedToEcdh(recipientPubCompressed)
	if err != nil {
		return nil, nil, fmt.Errorf("decode recipient pubkey: %w", err)
	}

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()
	ephPubCompressed, err := compressUncompressedP256(ephPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("compress ephemeral pubkey: %w", err)
	}

	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer zeroize(shared)

	fp := sha256.Sum256(recipientPubCompressed)

	info := make([]byte, 0, len(envelopeWrapInfoLabel)+len(configID))
	info = append(info, envelopeWrapInfoLabel...)
	info = append(info, configID...)

	kdk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, fp[:], info), kdk); err != nil {
		return nil, nil, fmt.Errorf("HKDF: %w", err)
	}
	defer zeroize(kdk)

	block, err := aes.NewCipher(kdk)
	if err != nil {
		return nil, nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("gcm nonce: %w", err)
	}
	ctWithTag := gcm.Seal(nil, nonce, dek, fp[:])
	if len(ctWithTag) != len(dek)+16 {
		return nil, nil, fmt.Errorf("unexpected gcm output length: %d", len(ctWithTag))
	}

	wrap := make([]byte, 0, envelopeWrapLen)
	wrap = append(wrap, ephPubCompressed...)
	wrap = append(wrap, nonce...)
	wrap = append(wrap, ctWithTag...)
	if len(wrap) != envelopeWrapLen {
		return nil, nil, fmt.Errorf("wrap length %d, want %d", len(wrap), envelopeWrapLen)
	}
	return wrap, fp[:], nil
}

// chachaPoly1305Encrypt seals plaintext with ChaCha20-Poly1305 under key/nonce,
// binding aad as associated data.
func chachaPoly1305Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new chacha20poly1305: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("nonce len %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// chachaPoly1305Decrypt is the inverse of chachaPoly1305Encrypt.
func chachaPoly1305Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new chacha20poly1305: %w", err)
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// signP1363 signs SHA-256(msg) with the ECDSA key and returns the 64-byte
// P1363 form (r||s, 32 bytes each, big-endian, zero-padded).
func signP1363(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// compressP256 encodes a P-256 public key in 33-byte SEC1 compressed form.
func compressP256(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not P-256")
	}
	out := make([]byte, envelopeP256CompLen)
	if pub.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xBytes := pub.X.Bytes()
	copy(out[envelopeP256CompLen-len(xBytes):], xBytes)
	return out, nil
}

// compressUncompressedP256 converts a 65-byte uncompressed P-256 point (0x04
// prefix) to 33-byte compressed form.
func compressUncompressedP256(uncompressed []byte) ([]byte, error) {
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return nil, fmt.Errorf("not P-256 uncompressed (got %d bytes, prefix 0x%02x)",
			len(uncompressed), uncompressed[0])
	}
	out := make([]byte, envelopeP256CompLen)
	yLastByte := uncompressed[64]
	if yLastByte&1 == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[1:], uncompressed[1:33])
	return out, nil
}

// decodeP256CompressedToEcdh decodes a 33-byte compressed P-256 point into an
// ecdh.PublicKey for use as the static peer in ECDH.
func decodeP256CompressedToEcdh(compressed []byte) (*ecdh.PublicKey, error) {
	if len(compressed) != envelopeP256CompLen {
		return nil, fmt.Errorf("not 33 bytes: %d", len(compressed))
	}
	curve := elliptic.P256()

	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, fmt.Errorf("invalid compressed point")
	}
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	xb := x.Bytes()
	yb := y.Bytes()
	copy(uncompressed[1+32-len(xb):33], xb)
	copy(uncompressed[1+64-len(yb):65], yb)
	return ecdh.P256().NewPublicKey(uncompressed)
}

// envelopeDecoded is a parsed frame: the typed header plus the raw byte ranges
// needed to re-verify the signature and decrypt the body.
type envelopeDecoded struct {
	Header         envelopeHeader
	HeaderBytes    []byte
	BodyNonce      []byte
	BodyCiphertext []byte
	Signature      []byte
}

// decodeEnvelopeWire parses and length-checks a frame, rejecting bad magic,
// unknown versions, truncation, and trailing bytes after the signature.
func decodeEnvelopeWire(raw []byte) (*envelopeDecoded, error) {
	minLen := envelopeMagicLen + envelopeVersionLen + envelopeHeaderLenLen +
		envelopeBodyNonceLen + envelopeBodyLenLen + envelopeSignatureLen
	if len(raw) < minLen {
		return nil, fmt.Errorf("too short: %d bytes", len(raw))
	}
	off := 0
	if !bytes.Equal(raw[off:off+envelopeMagicLen], envelopeMagic) {
		return nil, fmt.Errorf("bad magic")
	}
	off += envelopeMagicLen
	if raw[off] != envelopeVersion {
		return nil, fmt.Errorf("unsupported version: %d", raw[off])
	}
	off += envelopeVersionLen
	headerLen := int(binary.BigEndian.Uint32(raw[off:]))
	off += envelopeHeaderLenLen
	if off+headerLen > len(raw) {
		return nil, fmt.Errorf("header truncated")
	}
	headerBytes := raw[off : off+headerLen]
	off += headerLen
	if off+envelopeBodyNonceLen > len(raw) {
		return nil, fmt.Errorf("body nonce truncated")
	}
	bodyNonce := raw[off : off+envelopeBodyNonceLen]
	off += envelopeBodyNonceLen
	bodyLen := int(binary.BigEndian.Uint32(raw[off:]))
	off += envelopeBodyLenLen
	if off+bodyLen > len(raw) {
		return nil, fmt.Errorf("body truncated")
	}
	bodyCipher := raw[off : off+bodyLen]
	off += bodyLen
	if off+envelopeSignatureLen != len(raw) {
		return nil, fmt.Errorf("trailing or missing signature: %d trailing bytes", len(raw)-off)
	}
	signature := raw[off : off+envelopeSignatureLen]

	var header envelopeHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	return &envelopeDecoded{
		Header:         header,
		HeaderBytes:    headerBytes,
		BodyNonce:      bodyNonce,
		BodyCiphertext: bodyCipher,
		Signature:      signature,
	}, nil
}

// ptrOrNil returns nil for the empty string, otherwise a pointer to s. Used for
// optional JSON fields that must serialize as null when absent.
func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// zeroize overwrites b with zeros to clear key material from memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
