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

// Sealed envelope minter (Go side). Mirrors the NpvTunnel client's
// sealed-envelope codec — same wire format, same canonical JSON, same KEM
// construction. The two implementations are the spec.
//
// What this file produces is byte-compatible with what the client
// parser consumes. The Go envelope_test.go does round-trip
// verification end-to-end (encode → decode → verify signature →
// unwrap → AEAD-decrypt body) so the Go side is self-validating
// even before the client parser sees it.

// ─── Wire constants (must match the client) ──

const (
	envelopeMagicLen      = 4
	envelopeVersion       = 1
	envelopeVersionLen    = 1
	envelopeHeaderLenLen  = 4
	envelopeBodyNonceLen  = 12
	envelopeBodyLenLen    = 4
	envelopeSignatureLen  = 64 // ECDSA P-256 IEEE P1363
	envelopeDEKLen        = 32 // ChaCha20-Poly1305 key
	envelopeConfigIDLen   = 16
	envelopeWrapLen       = 93 // eph_pk(33)+nonce(12)+ct(32)+tag(16)
	envelopeP256CompLen   = 33 // SEC 1 compressed P-256 pubkey
)

var envelopeMagic = []byte{0x4E, 0x50, 0x56, 0x53} // "NPVS"

var envelopeWrapInfoLabel = []byte("NPVS-v1-wrap")

// ─── Header schema (mirrors the client) ──────────────────────────

type envelopeHeader struct {
	V          int               `json:"v"`
	ConfigID   string            `json:"configId"`
	IssuedAt   string            `json:"issuedAt"`
	Creator    envelopeCreatorRef `json:"creator"`
	Policy     envelopePolicy    `json:"policy"`
	Recipients []envelopeRecipient `json:"recipients"`
}

type envelopeCreatorRef struct {
	Fp string `json:"fp"`
	Pk string `json:"pk"`
}

// envelopePolicy mirrors ConfigPolicy in the client. The client
// Json config uses `encodeDefaults = true` in the codec, so every
// field is emitted — we use `omitempty` only for `expiresAt`
// because the client type has it as nullable (`String?`) which
// serializes to `null` when null. To match exactly, we use a
// pointer and always include the key (writing `null` when unset).
//
// IMPORTANT: the client codec writes ALL fields including defaults,
// so even an unset boolean writes `false` not omitted. We match by
// not using `omitempty` on bools/strings — they always render.
type envelopePolicy struct {
	OnlyMobileNetwork   bool    `json:"onlyMobileNetwork"`
	AttestationLevel    string  `json:"attestationLevel"`
	ExpiresAt           *string `json:"expiresAt"`
	DisplayMessage      string  `json:"displayMessage"`
	CustomServerMessage string  `json:"customServerMessage"`
}

type envelopeRecipient struct {
	Fp   string `json:"fp"`
	Wrap string `json:"wrap"`
}

// ─── Issuer body (V2) shape ───────────────────────────────────────

// issuerBody mirrors IssuerBody in the client. Field
// names + Json config (encodeDefaults=false except `kind`) are
// preserved so the body bytes match what the client sealer would
// produce — required for the envelope signature to verify on the
// recipient side (the recipient re-canonicalizes and checks the sig).
type issuerBody struct {
	Kind          string  `json:"kind"`
	CreatorPubkey string  `json:"creatorPubkey"`
	IssuerURL     string  `json:"issuerUrl"`
	MinAppVersion *string `json:"minAppVersion,omitempty"`
}

const issuerBodyKindV2 = "v2-issuer"

// encodeIssuerBody marshals the body to its JSON wire form. The
// client codec uses `encodeDefaults = false` for this body
// specifically, so optional null fields are omitted entirely
// (mirrored here by omitempty on the pointer fields).
func encodeIssuerBody(b issuerBody) ([]byte, error) {
	// Marshal via encoding/json. The field declaration order in the
	// struct determines the wire field order — client emits them
	// in the same order via kotlinx-serialization. Order doesn't
	// affect the cryptographic hash (configFp is over canonical
	// header bytes, not body), but matches the client output for
	// readability.
	return json.Marshal(b)
}

// ─── Minter input + result ────────────────────────────────────────

// mintInput is everything the minter needs to produce one envelope.
type mintInput struct {
	// CreatorKey is the persisted creator signing key (loaded from
	// /var/lib/creator-server/creator-key.pem in production).
	CreatorKey *ecdsa.PrivateKey
	// RecipientPubKeys is the list of recipient P-256 compressed
	// 33-byte pubkeys this envelope is addressed to. For Phase-3
	// issuer-backed envelopes this is typically a single recipient.
	RecipientPubKeys [][]byte
	// IssuerURL is the creator-server's public /v1/issue endpoint.
	IssuerURL string
	// MinAppVersion is informational; recipients can warn if their
	// app is older.
	MinAppVersion string
	// ConfigID is 16 bytes; if nil the minter generates one.
	ConfigID []byte
	// IssuedAt is the wall-clock timestamp; if zero the minter
	// uses time.Now().UTC().
	IssuedAt time.Time
	// Policy controls the envelope policy fields. If nil, defaults
	// (no expiry, NONE attestation level) are used.
	Policy *envelopePolicy
}

// mintResult is what the minter hands back.
type mintResult struct {
	// EnvelopeBytes is the raw .npvs bytes — pass to recipient as
	// base64 over text channels, or as the file directly.
	EnvelopeBytes []byte
	// ConfigFp is base64url-no-pad of SHA-256(envelopeBytes) — an
	// integrity hash of the envelope file, informational only. Not a
	// routing key (see ConfigID) and not sent by the recipient; useful
	// for verifying an envelope file hasn't been corrupted in transit.
	ConfigFp string
	// ConfigID is the 16-byte stable identifier embedded in the
	// envelope header. This is the routing key: the operator pastes its
	// base64url form into configs.json, and the recipient echoes it back
	// in every /v1/issue request so the issuer can find the registry
	// entry. Stable across re-mints — re-mint with the same ConfigID to
	// update an envelope without breaking existing recipients.
	ConfigID []byte
}

// ─── Minter ───────────────────────────────────────────────────────

// mintIssuerEnvelope produces a fully-sealed V2 issuer envelope per
// the mintInput. Caller is responsible for distributing the result
// to the recipient + registering the configId in configs.json.
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

	// configId — random 16 bytes if not supplied.
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

	// IssuedAt default.
	issuedAt := in.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	issuedAtStr := issuedAt.UTC().Format("2006-01-02T15:04:05.999999999Z")
	// kotlinx-datetime's Instant.toString() uses ISO-8601 with `Z`
	// suffix and variable fractional seconds. For matching purposes
	// we don't need byte-identical timestamps — the receiver doesn't
	// re-canonicalize the header, it uses the bytes as-is for AAD +
	// signature.

	// Policy default.
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

	// Creator identity.
	creatorPub, err := compressP256(&in.CreatorKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("compress creator pubkey: %w", err)
	}
	creatorFp := sha256.Sum256(creatorPub)

	// Fresh DEK + body nonce for this seal.
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

	// Wrap DEK for each recipient (§6.5).
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

	// Build header.
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

	// Encode + seal the body.
	bodyBytes, err := encodeIssuerBody(issuerBody{
		Kind:          issuerBodyKindV2,
		CreatorPubkey: b64url.EncodeToString(creatorPub),
		IssuerURL:     in.IssuerURL,
		MinAppVersion: ptrOrNil(in.MinAppVersion),
	})
	if err != nil {
		return nil, fmt.Errorf("encode issuer body: %w", err)
	}

	bodyCipher, err := chachaPoly1305Encrypt(dek, bodyNonce, headerBytes, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	// Sign over magic||version||headerLen||header||bodyNonce||bodyLen||bodyCipher.
	toSign := buildSignedRange(headerBytes, bodyNonce, bodyCipher)
	sig, err := signP1363(in.CreatorKey, toSign)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	// Encode wire layout.
	envelopeBytes := encodeEnvelopeWire(headerBytes, bodyNonce, bodyCipher, sig)
	configFp := sha256.Sum256(envelopeBytes)

	return &mintResult{
		EnvelopeBytes: envelopeBytes,
		ConfigFp:      b64url.EncodeToString(configFp[:]),
		ConfigID:      configID,
	}, nil
}

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

// ─── KEM wrap (§6.5) ──────────────────────────────────────────────

// ecdhEphemeralWrap implements the §6.5 sender step:
//
//	1. Generate ephemeral P-256 keypair.
//	2. shared = ECDH(eph_sk, recipient_pk).x
//	3. kdk    = HKDF-SHA256(salt=fp, ikm=shared, info=label||configId, L=32)
//	4. nonce  = random(12)
//	5. ct||tag = AES-256-GCM.encrypt(key=kdk, nonce=nonce, aad=fp, pt=dek)
//	6. wrap   = eph_pk_compressed || nonce || ct || tag   (93 bytes)
//
// Returns (wrap, fp_of_recipient).
func ecdhEphemeralWrap(recipientPubCompressed, configID, dek []byte) ([]byte, []byte, error) {
	curve := ecdh.P256()

	// Decode recipient pubkey from SEC1 compressed → ecdh.PublicKey.
	recipientPub, err := decodeP256CompressedToEcdh(recipientPubCompressed)
	if err != nil {
		return nil, nil, fmt.Errorf("decode recipient pubkey: %w", err)
	}

	// Generate ephemeral keypair.
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPubBytes := ephPriv.PublicKey().Bytes() // 65-byte uncompressed (0x04||X||Y)
	ephPubCompressed, err := compressUncompressedP256(ephPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("compress ephemeral pubkey: %w", err)
	}

	// ECDH(eph_sk, recipient_pk) → 32-byte shared X.
	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer zeroize(shared)

	// fp = SHA-256(recipient_pk_compressed). Used as HKDF salt + GCM AAD.
	fp := sha256.Sum256(recipientPubCompressed)

	// info = "NPVS-v1-wrap" || configId  (28 bytes for the standard configId).
	info := make([]byte, 0, len(envelopeWrapInfoLabel)+len(configID))
	info = append(info, envelopeWrapInfoLabel...)
	info = append(info, configID...)

	// HKDF-SHA256(salt=fp, ikm=shared, info=info, L=32).
	kdk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, fp[:], info), kdk); err != nil {
		return nil, nil, fmt.Errorf("HKDF: %w", err)
	}
	defer zeroize(kdk)

	// AES-256-GCM(key=kdk, aad=fp, pt=dek).
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

	// wrap = eph_pk_compressed(33) || nonce(12) || ct(32) || tag(16) = 93 bytes.
	wrap := make([]byte, 0, envelopeWrapLen)
	wrap = append(wrap, ephPubCompressed...)
	wrap = append(wrap, nonce...)
	wrap = append(wrap, ctWithTag...)
	if len(wrap) != envelopeWrapLen {
		return nil, nil, fmt.Errorf("wrap length %d, want %d", len(wrap), envelopeWrapLen)
	}
	return wrap, fp[:], nil
}

// ─── ChaCha20-Poly1305 (body cipher) ──────────────────────────────

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

func chachaPoly1305Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new chacha20poly1305: %w", err)
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// ─── ECDSA P-256 IEEE P1363 signing ───────────────────────────────

// signP1363 produces a fixed-64-byte signature (r || s, each 32 bytes
// big-endian, left-padded with zeros). Matches the client
// `ecdsaDerToP1363` output. Re-used from the existing signReceipt
// helper logic in crypto.go but operating on raw bytes here.
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

// ─── P-256 compressed-form helpers ────────────────────────────────

// compressP256 emits the SEC 1 compressed form (0x02|0x03 prefix +
// 32-byte X) from a crypto/ecdsa public key.
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

// compressUncompressedP256 takes the 65-byte uncompressed form
// (0x04 || X || Y) — which is what crypto/ecdh's PublicKey.Bytes()
// returns — and produces the 33-byte compressed form.
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

// decodeP256CompressedToEcdh decodes a 33-byte SEC 1 compressed
// point into a crypto/ecdh.PublicKey for use with ECDH operations.
// Goes via elliptic.UnmarshalCompressed (the only stdlib path) to
// recover X+Y, then re-emits as uncompressed for crypto/ecdh.
func decodeP256CompressedToEcdh(compressed []byte) (*ecdh.PublicKey, error) {
	if len(compressed) != envelopeP256CompLen {
		return nil, fmt.Errorf("not 33 bytes: %d", len(compressed))
	}
	curve := elliptic.P256()
	// nolint:staticcheck // SA1019: UnmarshalCompressed is the only stdlib
	// API that decompresses P-256 points and yields X,Y suitable for
	// the crypto/ecdh round-trip below. crypto/ecdh.PublicKey takes
	// uncompressed bytes only.
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

// ─── Verify + unseal (for round-trip testing) ─────────────────────

// envelopeDecoded is what decodeEnvelopeWire returns.
type envelopeDecoded struct {
	Header         envelopeHeader
	HeaderBytes    []byte
	BodyNonce      []byte
	BodyCiphertext []byte
	Signature      []byte
}

// decodeEnvelopeWire parses the wire format back into its parts.
// Used by envelope_test.go for round-trip tests and (potentially)
// by future tooling — there's no production code path that needs
// this on the server side today.
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

// ─── small helpers ────────────────────────────────────────────────

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
