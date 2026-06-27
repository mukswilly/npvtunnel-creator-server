package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// appleAppAttestVerifier validates an App Attest attestation object against a
// pool of trusted roots. App Attest is an Apple attestation scheme in which a
// hardware-backed key produces a CBOR attestation object whose certificate
// chain anchors at Apple's App Attest root.
type appleAppAttestVerifier struct {
	roots *x509.CertPool
}

// newAppleAppAttestVerifier returns a verifier that anchors attestation
// certificate chains at the given root pool.
func newAppleAppAttestVerifier(roots *x509.CertPool) *appleAppAttestVerifier {
	return &appleAppAttestVerifier{roots: roots}
}

// appleAppAttestOID identifies the credCert extension that App Attest places in
// the leaf certificate. Its value carries the nonce that binds the attestation
// to a specific challenge.
var appleAppAttestOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// aaguidProd and aaguidDev are the two fixed AAGUID values App Attest writes
// into authenticator data: the production environment and the development
// environment, respectively. Each is a fixed 16-byte marker.
var (
	aaguidProd = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDev  = []byte("appattestdevelop")
)

// Verify satisfies the AttestationVerifier interface but cannot complete a
// verification on its own: App Attest binds the attestation to an application
// identity that lives in the config's policy. It always returns an unverified
// verdict directing the caller to verifyWithAppID, which takes that identity.
func (v *appleAppAttestVerifier) Verify(blob AttestationBlob) (Verdict, error) {

	return Verdict{
		Verified: false,
		Reason:   "apple-app-attest requires appId from policy; use verifyWithAppID",
	}, nil
}

// verifyWithAppID performs the full App Attest check for the given application
// identifier (formatted TEAMID.bundle.id). It decodes the CBOR attestation
// object, validates the certificate chain to a trusted root, confirms the nonce
// binds the attestation to blob.Nonce, and confirms the authenticator data
// matches appID and the leaf key. The returned Verdict reports whether the
// chain anchored at a trusted root and carries a human-readable Reason; a
// non-nil error is returned only for malformed inputs that cannot be decoded.
func (v *appleAppAttestVerifier) verifyWithAppID(blob AttestationBlob, appID string) (Verdict, error) {
	if blob.Platform != "IOS" {
		return Verdict{Verified: false, Reason: "non-iOS platform"}, nil
	}
	if blob.Token == "" {
		return Verdict{Verified: false, Reason: "empty token"}, nil
	}
	if v.roots == nil {
		return Verdict{Verified: false, Reason: "verifier has no roots pool configured"}, nil
	}
	if appID == "" {
		return Verdict{
			Verified: false,
			Reason:   "apple-app-attest requires policy.appId (TEAMID.bundle.id); none configured",
		}, nil
	}

	// blob.Token is the base64url-encoded CBOR attestation object; blob.Nonce
	// is the base64url-encoded challenge that the attestation must bind to.
	tokenBytes, err := b64url.DecodeString(blob.Token)
	if err != nil {
		return Verdict{}, fmt.Errorf("decode token base64: %w", err)
	}

	challengeBytes, err := b64url.DecodeString(blob.Nonce)
	if err != nil {
		return Verdict{}, fmt.Errorf("decode nonce base64: %w", err)
	}

	att, err := decodeAppAttestObject(tokenBytes)
	if err != nil {
		return Verdict{}, fmt.Errorf("decode CBOR attestation: %w", err)
	}
	// App Attest objects carry the fixed format label "apple-appattest" and an
	// x5c certificate chain in the attestation statement.
	if att.Fmt != "apple-appattest" {
		return Verdict{Verified: false, Reason: "unexpected fmt: " + att.Fmt}, nil
	}
	if len(att.AttStmt.X5c) == 0 {
		return Verdict{Verified: false, Reason: "empty x5c chain"}, nil
	}

	// Parse the DER-encoded x5c entries into certificates, leaf first.
	chain := make([]*x509.Certificate, 0, len(att.AttStmt.X5c))
	for i, certDER := range att.AttStmt.X5c {
		c, err := x509.ParseCertificate(certDER)
		if err != nil {
			return Verdict{}, fmt.Errorf("parse cert %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	leaf := chain[0]

	// Confirm each certificate is signed by the next one up the chain.
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return Verdict{
				Verified: false,
				Reason:   fmt.Sprintf("chain link %d signature invalid: %v", i, err),
			}, nil
		}
	}

	// Anchor the leaf at one of the configured roots, treating every
	// non-leaf certificate as a candidate intermediate. trustedRoot records
	// whether a valid path to a trusted root exists; the value is reported in
	// the verdict and gates the final Verified result.
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Now(),
	}
	_, verifyErr := leaf.Verify(verifyOpts)
	trustedRoot := verifyErr == nil

	// Recompute the expected nonce: SHA-256 over authData concatenated with the
	// SHA-256 of the challenge, matching the value App Attest embeds in the
	// leaf's credCert extension.
	clientDataHash := sha256.Sum256(challengeBytes)
	composite := append([]byte{}, att.AuthData...)
	composite = append(composite, clientDataHash[:]...)
	expectedNonce := sha256.Sum256(composite)

	extractedNonce, err := extractAppAttestNonce(leaf)
	if err != nil {
		return Verdict{
			Verified: false,
			Reason:   "extract credCert nonce: " + err.Error(),
		}, nil
	}
	// The embedded nonce must equal the recomputed one, proving the attestation
	// was produced for this exact challenge.
	if !bytesEqualConstantTime(expectedNonce[:], extractedNonce) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "credCert nonce mismatch (challenge does not match attestation)",
		}, nil
	}

	ad, err := parseAppAttestAuthData(att.AuthData)
	if err != nil {
		return Verdict{
			Verified:    trustedRoot,
			TrustedRoot: trustedRoot,
			Reason:      "parse authData: " + err.Error(),
		}, nil
	}

	// The authenticator data's rpIdHash must equal SHA-256 of the expected
	// application identifier, tying the attestation to the intended app.
	appIDHash := sha256.Sum256([]byte(appID))
	if !bytesEqualConstantTime(ad.rpIDHash, appIDHash[:]) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "rpIdHash does not match SHA256(policy.appId)",
		}, nil
	}

	leafPubKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return Verdict{Verified: false, Reason: "leaf cert public key is not ECDSA"}, nil
	}
	// The credentialId (key identifier) must equal SHA-256 of the leaf's public
	// key in uncompressed point form, binding the attested key to this leaf.
	pubUncompressed := marshalUncompressed(leafPubKey)
	expectedKeyID := sha256.Sum256(pubUncompressed)
	if !bytesEqualConstantTime(ad.credentialID, expectedKeyID[:]) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "credentialId does not match SHA256(leaf pubkey)",
		}, nil
	}

	// The AAGUID must be one of the two recognized App Attest markers;
	// anything else is rejected. Record which environment it identifies for
	// the verdict's Reason.
	aaguidKind := "unknown"
	switch {
	case bytesEqualConstantTime(ad.aaguid, aaguidProd):
		aaguidKind = "prod"
	case bytesEqualConstantTime(ad.aaguid, aaguidDev):
		aaguidKind = "dev"
	default:
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      fmt.Sprintf("aaguid is not an Apple App Attest value: %x", ad.aaguid),
		}, nil
	}

	// All structural and binding checks passed; the only remaining factor is
	// whether the chain anchored at a trusted root. App Attest keys are always
	// hardware-backed, so the verdict reports that unconditionally. The boot
	// state and lock fields do not apply to this scheme and are left empty.
	verdict := Verdict{
		Verified:    trustedRoot,
		TrustedRoot: trustedRoot,

		SecurityLevel:  "strongbox",
		HardwareBacked: true,

		VerifiedBootState: "",
		DeviceLocked:      false,
	}
	if trustedRoot {
		verdict.Reason = "App Attest chain verified against Apple root; aaguid=" + aaguidKind
	} else {
		verdict.Reason = "chain does not anchor at Apple App Attest root: " + verifyErr.Error()
	}
	return verdict, nil
}

// appAttestObject is the top-level CBOR attestation object: a format label, an
// attestation statement, and the raw authenticator data.
type appAttestObject struct {
	Fmt      string        `cbor:"fmt"`
	AttStmt  appAttestStmt `cbor:"attStmt"`
	AuthData []byte        `cbor:"authData"`
	_extra   map[string]interface{}
}

// appAttestStmt is the attestation statement: the certificate chain (x5c, each
// entry DER-encoded) and an opaque receipt.
type appAttestStmt struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// decodeAppAttestObject CBOR-decodes the raw attestation object bytes.
func decodeAppAttestObject(raw []byte) (*appAttestObject, error) {
	var obj appAttestObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

// extractAppAttestNonce returns the nonce held in the leaf certificate's
// credCert extension. The extension value is a SEQUENCE whose [1]
// context-specific element wraps an OCTET STRING containing the nonce. It
// returns an error if the extension is absent or not shaped as expected.
func extractAppAttestNonce(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(appleAppAttestOID) {
			continue
		}

		// The extension value must be a single universal SEQUENCE with no
		// trailing bytes.
		var outer asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &outer)
		if err != nil {
			return nil, fmt.Errorf("unmarshal outer SEQUENCE: %w", err)
		}
		if len(rest) != 0 {
			return nil, errors.New("trailing bytes after credCert SEQUENCE")
		}
		if outer.Tag != asn1.TagSequence || outer.Class != asn1.ClassUniversal {
			return nil, fmt.Errorf("expected outer SEQUENCE, got tag=%d class=%d",
				outer.Tag, outer.Class)
		}

		// Walk the SEQUENCE elements looking for the [1] context-specific
		// entry, whose contents are the OCTET STRING holding the nonce.
		body := outer.Bytes
		for len(body) > 0 {
			var elem asn1.RawValue
			next, err := asn1.Unmarshal(body, &elem)
			if err != nil {
				return nil, fmt.Errorf("iterate credCert body: %w", err)
			}
			body = next
			if elem.Class == asn1.ClassContextSpecific && elem.Tag == 1 {

				var nonce []byte
				if _, err := asn1.Unmarshal(elem.Bytes, &nonce); err != nil {
					return nil, fmt.Errorf("unmarshal nonce OCTET STRING: %w", err)
				}
				return nonce, nil
			}
		}
		return nil, errors.New("credCert SEQUENCE missing [1] tagged nonce")
	}
	return nil, errors.New("leaf cert missing App Attest credCert extension")
}

// appAttestAuthData holds the fields parsed out of the authenticator data:
// the relying-party ID hash, the flags byte, the signature counter, the
// AAGUID, and the attested credential (key) identifier.
type appAttestAuthData struct {
	rpIDHash     []byte
	flags        byte
	signCounter  uint32
	aaguid       []byte
	credentialID []byte
}

// parseAppAttestAuthData parses the fixed-layout authenticator data: a 32-byte
// rpIdHash, a flags byte, a 4-byte big-endian signature counter, a 16-byte
// AAGUID, a 2-byte big-endian credential-ID length, and the credential ID
// itself. It requires the attested-credential-data (AT) flag to be set and the
// signature counter to be zero, as App Attest mandates for the initial
// attestation, and returns an error on any short or truncated input.
func parseAppAttestAuthData(raw []byte) (*appAttestAuthData, error) {

	// 32 (rpIdHash) + 1 (flags) + 4 (counter) + 16 (AAGUID) + 2 (credID len).
	if len(raw) < 55 {
		return nil, fmt.Errorf("authData too short (%d bytes; need >= 55)", len(raw))
	}
	ad := &appAttestAuthData{
		rpIDHash:    raw[:32],
		flags:       raw[32],
		signCounter: binary.BigEndian.Uint32(raw[33:37]),
		aaguid:      raw[37:53],
	}
	// The 2-byte length at offset 53 declares how many credential-ID bytes
	// follow; reject a value that would run past the buffer.
	credIDLen := int(binary.BigEndian.Uint16(raw[53:55]))
	if 55+credIDLen > len(raw) {
		return nil, fmt.Errorf("credentialId truncated: declared %d bytes, %d remaining",
			credIDLen, len(raw)-55)
	}
	ad.credentialID = raw[55 : 55+credIDLen]

	// Bit 0x40 is the attested-credential-data flag; it must be present.
	if ad.flags&0x40 == 0 {
		return nil, errors.New("authData flags missing AT bit (attestation flag)")
	}

	if ad.signCounter != 0 {
		return nil, fmt.Errorf("authData signCounter must be 0 for App Attest attestation, got %d",
			ad.signCounter)
	}
	return ad, nil
}

// marshalUncompressed encodes an EC public key in SEC1 uncompressed point form:
// a 0x04 prefix followed by the fixed-width big-endian X and Y coordinates.
// Each coordinate is left-padded with zeros to the curve's byte width so the
// output length is independent of the integer magnitudes.
func marshalUncompressed(pub *ecdsa.PublicKey) []byte {
	curveByteSize := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	out := make([]byte, 1+2*curveByteSize)
	out[0] = 0x04
	copy(out[1+curveByteSize-len(x):], x)
	copy(out[1+2*curveByteSize-len(y):], y)
	return out
}

// bytesEqualConstantTime reports whether a and b are equal, comparing in time
// that does not depend on where they first differ. Unequal lengths return false
// immediately.
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
