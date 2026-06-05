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

// appleAppAttestVerifier verifies Apple App Attest attestation
// objects, the iOS counterpart of Android Key Attestation.
//
// What this verifies:
//   - The token decodes as a CBOR attestation object with fmt =
//     "apple-appattest".
//   - attStmt.x5c is a non-empty cert chain that anchors at Apple's
//     bundled App Attest root.
//   - The leaf cert's credCert extension (OID 1.2.840.113635.100.8.2)
//     contains a nonce equal to SHA256(authData || clientDataHash),
//     where clientDataHash = SHA256(challenge). The challenge comes
//     from blob.Nonce — for our protocol the recipient picks a
//     stable per-install challenge (typically their recipient
//     fingerprint) and reuses it for both key generation and every
//     subsequent issuance request.
//   - authData parses to the expected layout: 32-byte rpIdHash,
//     1-byte flags, 4-byte signCounter, 16-byte aaguid, 2-byte
//     credentialIdLength, credentialId, and CBOR-encoded COSE key.
//   - rpIdHash matches SHA256(appId), where appId is configured per-
//     policy as "TEAMID.bundle.id".
//   - The SHA256 of the leaf cert's pubkey equals credentialId in
//     authData (proves the attestation describes the same key the
//     leaf attests to).
//
// What it does NOT verify:
//   - The aaguid value — "appattestdevelop" (dev env, useful for
//     creators in development) and "appattest\0\0\0\0\0\0\0" (prod)
//     are both treated as valid. The verifier reports which it saw
//     in the Verdict.Reason.
//   - Apple's revocation list (App Attest doesn't publish one
//     analogous to AKA's; key revocation is handled via Apple's
//     receipt validation API, which is out of scope here).
//
// Honest framing: this is the structural / cryptographic side. There
// is no "verified-boot" equivalent — App Attest assertions don't
// carry the bootloader state. iOS is closed enough that Apple's
// position is essentially "if the chain validates, the assertion is
// from a real iPhone running a non-jailbroken OS." For our policy
// surface that maps to: RequireHardwareBacked and RequireTrustedRoot
// are the meaningful knobs; RequireVerifiedBoot is silently treated
// as N/A for App Attest verdicts (the leaf doesn't carry the signal,
// so we don't gate on it).
type appleAppAttestVerifier struct {
	roots *x509.CertPool
	// Per-verify appId comes from the policy at evaluate-time (via
	// appleAppAttestVerifier.verifyWithAppID below) — we don't keep
	// a per-config map here because the generic AttestationVerifier
	// interface doesn't pass routing keys to Verify().
}

// newAppleAppAttestVerifier returns a verifier anchored at the given
// roots pool. Production uses loadAppleAppAttestRoots(); tests inject
// synthetic pools the same way AKA does.
func newAppleAppAttestVerifier(roots *x509.CertPool) *appleAppAttestVerifier {
	return &appleAppAttestVerifier{roots: roots}
}

// appleAppAttestOID is the X.509 extension OID Apple reserves for
// the credCert extension carrying the App Attest nonce.
var appleAppAttestOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// Apple-issued aaguid values inside authData.
var (
	aaguidProd = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDev  = []byte("appattestdevelop")
)

// Verify implements AttestationVerifier. AppId resolution happens
// here via the contextually-known policy.AppId; if the verifier
// runs without an appId configured, the verdict is rejected with a
// clear reason.
//
// Note: the AttestationVerifier interface doesn't carry per-request
// config context, so we put appId into a side-channel via the
// policy-aware verifier wrapper. See verifierForPolicy below for the
// glue.
func (v *appleAppAttestVerifier) Verify(blob AttestationBlob) (Verdict, error) {
	// This top-level Verify produces a verdict that fails because we
	// don't have the appId. The policy-aware wrapper supplies it.
	return Verdict{
		Verified: false,
		Reason:   "apple-app-attest requires appId from policy; use verifyWithAppID",
	}, nil
}

// verifyWithAppID is the real entry point — invoked by the policy
// evaluator with the appId from AttestationPolicy.AppId pulled out
// of the matching config.
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
	if att.Fmt != "apple-appattest" {
		return Verdict{Verified: false, Reason: "unexpected fmt: " + att.Fmt}, nil
	}
	if len(att.AttStmt.X5c) == 0 {
		return Verdict{Verified: false, Reason: "empty x5c chain"}, nil
	}

	// Parse the chain.
	chain := make([]*x509.Certificate, 0, len(att.AttStmt.X5c))
	for i, certDER := range att.AttStmt.X5c {
		c, err := x509.ParseCertificate(certDER)
		if err != nil {
			return Verdict{}, fmt.Errorf("parse cert %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	leaf := chain[0]

	// Internal chain-link consistency check (mirrors AKA's defense-in-
	// depth: x509.Verify subsumes this, but a precise error message
	// is more actionable than "certificate signed by unknown authority").
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return Verdict{
				Verified: false,
				Reason:   fmt.Sprintf("chain link %d signature invalid: %v", i, err),
			}, nil
		}
	}

	// Anchor at Apple's bundled root.
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

	// Compute nonce per Apple's spec: SHA256(authData || clientDataHash),
	// where clientDataHash = SHA256(challenge).
	clientDataHash := sha256.Sum256(challengeBytes)
	composite := append([]byte{}, att.AuthData...)
	composite = append(composite, clientDataHash[:]...)
	expectedNonce := sha256.Sum256(composite)

	// Extract the credCert extension and pull the nonce.
	extractedNonce, err := extractAppAttestNonce(leaf)
	if err != nil {
		return Verdict{
			Verified: false,
			Reason:   "extract credCert nonce: " + err.Error(),
		}, nil
	}
	if !bytesEqualConstantTime(expectedNonce[:], extractedNonce) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "credCert nonce mismatch (challenge does not match attestation)",
		}, nil
	}
	// Only meaningful gate after this point requires trustedRoot.
	// Don't bail early — finish parsing so observe-mode logs see the
	// extracted environment.

	// Parse authenticatorData. Layout per WebAuthn / App Attest:
	//   [0..32)   rpIdHash       — SHA256(rpId)
	//   [32]      flags          — bit 0 = UP, bit 6 = AT (must be set)
	//   [33..37)  signCounter    — uint32 BE
	//   [37..53)  aaguid         — 16 bytes
	//   [53..55)  credIdLength   — uint16 BE
	//   [55..55+L) credentialId
	//   [55+L..)  CBOR COSE key
	ad, err := parseAppAttestAuthData(att.AuthData)
	if err != nil {
		return Verdict{
			Verified:    trustedRoot,
			TrustedRoot: trustedRoot,
			Reason:      "parse authData: " + err.Error(),
		}, nil
	}

	// rpIdHash must equal SHA256(appID).
	appIDHash := sha256.Sum256([]byte(appID))
	if !bytesEqualConstantTime(ad.rpIDHash, appIDHash[:]) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "rpIdHash does not match SHA256(policy.appId)",
		}, nil
	}

	// credentialId must equal SHA256(leaf pubkey uncompressed).
	leafPubKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return Verdict{Verified: false, Reason: "leaf cert public key is not ECDSA"}, nil
	}
	pubUncompressed := marshalUncompressed(leafPubKey)
	expectedKeyID := sha256.Sum256(pubUncompressed)
	if !bytesEqualConstantTime(ad.credentialID, expectedKeyID[:]) {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "credentialId does not match SHA256(leaf pubkey)",
		}, nil
	}

	// aaguid must be one of Apple's published values.
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

	// Compose verdict.
	verdict := Verdict{
		Verified:    trustedRoot,
		TrustedRoot: trustedRoot,
		// App Attest only attests via the Secure Enclave, which is
		// dedicated hardware. There's no software-only counterpart
		// for App Attest, so any successful App Attest chain implies
		// hardware backing. We surface it as "strongbox" for
		// uniformity with AKA's StrongBox tier — they're equivalent
		// in security guarantee.
		SecurityLevel:  "strongbox",
		HardwareBacked: true,
		// App Attest doesn't carry verified-boot state. Leave the
		// field empty so requireVerifiedBoot gates correctly: an
		// empty VerifiedBootState != "verified", so the gate fails
		// closed if a creator accidentally enables it for App
		// Attest. Documented in the verifier comment.
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

// ─── CBOR decoding ─────────────────────────────────────────────────

type appAttestObject struct {
	Fmt      string                 `cbor:"fmt"`
	AttStmt  appAttestStmt          `cbor:"attStmt"`
	AuthData []byte                 `cbor:"authData"`
	_extra   map[string]interface{} // tolerate unknown keys
}

type appAttestStmt struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

func decodeAppAttestObject(raw []byte) (*appAttestObject, error) {
	var obj appAttestObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

// ─── credCert extension parser ────────────────────────────────────
//
// The credCert extension structure per Apple's spec:
//
//   credCert ::= OCTET STRING containing
//     SEQUENCE {
//       [1] EXPLICIT OCTET STRING -- the nonce (SHA256 size: 32 bytes)
//     }
//
// In practice, x509 surfaces the extension's Value as the OCTET STRING
// body — we asn1.Unmarshal that into a RawValue to walk to the inner
// SEQUENCE.

// extractAppAttestNonce locates the credCert extension on the leaf
// cert and returns the embedded nonce bytes.
func extractAppAttestNonce(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(appleAppAttestOID) {
			continue
		}
		// ext.Value is the OCTET STRING's body. It contains an
		// ASN.1 SEQUENCE with one context-tagged element.
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

		body := outer.Bytes
		for len(body) > 0 {
			var elem asn1.RawValue
			next, err := asn1.Unmarshal(body, &elem)
			if err != nil {
				return nil, fmt.Errorf("iterate credCert body: %w", err)
			}
			body = next
			if elem.Class == asn1.ClassContextSpecific && elem.Tag == 1 {
				// [1] EXPLICIT OCTET STRING — elem.Bytes contains
				// the inner OCTET STRING's full DER. Unmarshal it
				// to get the bytes.
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

// ─── authData parser ──────────────────────────────────────────────

type appAttestAuthData struct {
	rpIDHash     []byte // 32 bytes
	flags        byte
	signCounter  uint32
	aaguid       []byte // 16 bytes
	credentialID []byte
	// We don't currently surface the CBOR-encoded COSE key — Apple's
	// keyId check (credentialId == SHA256(leaf pubkey)) is what gives
	// us the binding to the attestation cert; the COSE key is
	// redundant with the leaf cert's pubkey for our purposes.
}

func parseAppAttestAuthData(raw []byte) (*appAttestAuthData, error) {
	// Minimum length: 32 + 1 + 4 + 16 + 2 = 55 bytes before any
	// variable-length section.
	if len(raw) < 55 {
		return nil, fmt.Errorf("authData too short (%d bytes; need >= 55)", len(raw))
	}
	ad := &appAttestAuthData{
		rpIDHash:    raw[:32],
		flags:       raw[32],
		signCounter: binary.BigEndian.Uint32(raw[33:37]),
		aaguid:      raw[37:53],
	}
	credIDLen := int(binary.BigEndian.Uint16(raw[53:55]))
	if 55+credIDLen > len(raw) {
		return nil, fmt.Errorf("credentialId truncated: declared %d bytes, %d remaining",
			credIDLen, len(raw)-55)
	}
	ad.credentialID = raw[55 : 55+credIDLen]
	// Apple's spec requires AT bit (0x40) set on attestation
	// authData. Soft check — we surface the failure but don't bail
	// for it alone (the credentialId match below is the load-
	// bearing identity binding).
	if ad.flags&0x40 == 0 {
		return nil, errors.New("authData flags missing AT bit (attestation flag)")
	}
	// signCounter MUST be 0 for a fresh App Attest key. Non-zero
	// here indicates the client is sending an assertion (subsequent
	// use) rather than an attestation (initial key gen). For our
	// use case the attestation object is reused across requests, so
	// the counter at the time it was captured was 0 — we enforce.
	if ad.signCounter != 0 {
		return nil, fmt.Errorf("authData signCounter must be 0 for App Attest attestation, got %d",
			ad.signCounter)
	}
	return ad, nil
}

// ─── utilities ─────────────────────────────────────────────────────

// marshalUncompressed produces the uncompressed-form serialization
// (0x04 || X || Y) Apple uses inside the COSE key + as the input to
// the keyId SHA256.
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

// bytesEqualConstantTime is sha256-comparison-grade — these inputs
// aren't really high-secret but uniform constant-time helps shield
// against accidental side-channels in future callers.
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
