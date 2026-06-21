package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// androidKeyAttestationVerifier parses Android hardware key-attestation
// evidence and extracts a Verdict.
//
// What it verifies:
//   - The token decodes as a length-prefixed DER cert chain.
//   - Each cert in the chain parses as a well-formed X.509.
//   - Each cert's signature is checked against the next cert in the
//     chain (cryptographic chain consistency).
//   - The chain anchors at one of Google's published hardware
//     attestation roots, bundled in aka_roots.go. Chains whose root is
//     unknown to us produce Verdict.TrustedRoot = false AND
//     Verdict.Verified = false.
//   - The leaf certificate contains the Android Key Attestation
//     extension (OID 1.3.6.1.4.1.11129.2.1.17).
//   - The extension's ASN.1 structure decodes to expected types.
//   - attestationSecurityLevel is extracted from the extension.
//
// What it does NOT verify:
//   - Revocation status against Google's attestation status list
//     (https://android.googleapis.com/attestation/status). A device
//     whose attestation key Google has flagged for known compromise
//     still passes here. A fetch-and-cache revocation gate was built
//     and then deliberately removed: it was fail-open (skipped whenever
//     the feed was unreachable — and a censored-region issuer often
//     can't reach Google at all), it lagged real compromise by weeks,
//     and it bought nothing against the primary threat (a rooted
//     recipient extracts the config inside the ~1h credential window,
//     long before any feed could flag the key). Not worth the standing
//     network dependency + cache machinery.

// androidKeyAttestationOID is the X.509 extension OID Google reserves
// for the attestation key-description structure.
// Per https://source.android.com/docs/security/features/keystore/attestation
var androidKeyAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Security level values from the KeyDescription ASN.1 structure.
// Enum encoded as ASN.1 ENUMERATED in the extension.
const (
	akaSecurityLevelSoftware           = 0
	akaSecurityLevelTrustedEnvironment = 1
	akaSecurityLevelStrongBox          = 2
)

// androidKeyAttestationVerifier is the AKA implementation of
// AttestationVerifier. The roots pool is a constructor-injected field
// (not a package global) so tests can build a verifier anchored at
// synthetic roots without touching the embedded production roots.
type androidKeyAttestationVerifier struct {
	// roots is the pool of trusted root certs. A chain whose final
	// cert is signed by one of these passes TrustedRoot=true. Nil
	// roots means "no trust anchor configured"; in that case Verify
	// rejects every input — fail closed.
	roots *x509.CertPool
}

// newAndroidKeyAttestationVerifier returns an AKA verifier anchored at
// the given roots pool. Production code path uses loadGoogleAkaRoots();
// tests inject their own synthetic pool.
func newAndroidKeyAttestationVerifier(roots *x509.CertPool) *androidKeyAttestationVerifier {
	return &androidKeyAttestationVerifier{roots: roots}
}

func (v *androidKeyAttestationVerifier) Verify(blob AttestationBlob) (Verdict, error) {
	if blob.Platform != "ANDROID" {
		return Verdict{Verified: false, Reason: "non-Android platform"}, nil
	}
	if blob.Token == "" {
		return Verdict{Verified: false, Reason: "empty token"}, nil
	}
	if v.roots == nil {
		// Fail closed. A verifier with no trust anchor can never
		// produce a meaningful TrustedRoot=true verdict, and the
		// policy layer treats Verified=true with TrustedRoot=false
		// as a useful signal only — here we don't even have that.
		return Verdict{
			Verified: false,
			Reason:   "verifier has no roots pool configured",
		}, nil
	}

	tokenBytes, err := b64url.DecodeString(blob.Token)
	if err != nil {
		return Verdict{}, fmt.Errorf("decode token base64: %w", err)
	}

	chain, err := parseLengthPrefixedChain(tokenBytes)
	if err != nil {
		return Verdict{}, fmt.Errorf("parse cert chain: %w", err)
	}
	if len(chain) == 0 {
		return Verdict{Verified: false, Reason: "empty cert chain"}, nil
	}

	// Internal chain-link consistency: each cert (except the final
	// one) must be signed by its successor. The chain-to-root step
	// below subsumes this for well-formed Google chains, but checking
	// here surfaces a clear error message instead of x509.Verify's
	// generic "x509: certificate signed by unknown authority" when
	// the chain is internally broken.
	for i := 0; i < len(chain)-1; i++ {
		child := chain[i]
		parent := chain[i+1]
		if err := child.CheckSignatureFrom(parent); err != nil {
			return Verdict{
				Verified: false,
				Reason:   fmt.Sprintf("chain link %d signature invalid: %v", i, err),
			}, nil
		}
	}

	// Anchor the chain at a Google root via x509.Verify. The
	// attestation chain lists the leaf first and the root
	// last; we put everything except the leaf into Intermediates so
	// x509.Verify can build the path.
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		// AKA leaves aren't WebPKI server / client certs and don't
		// carry the standard EKUs; ExtKeyUsageAny tells x509 not to
		// reject them on that ground.
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: time.Now(),
	}
	// Don't bail on x509.Verify failure here — fall through and still
	// parse the extension. The Verdict surfaces TrustedRoot=false +
	// the precise extension-derived security level; observe-mode logs
	// benefit from seeing both signals, and the policy layer decides
	// whether TrustedRoot=false is a reject.
	_, verifyErr := leaf.Verify(verifyOpts)
	trustedRoot := verifyErr == nil

	// Find the attestation extension in the leaf cert.
	var extBytes []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(androidKeyAttestationOID) {
			extBytes = ext.Value
			break
		}
	}
	if extBytes == nil {
		return Verdict{
			Verified:    false,
			TrustedRoot: trustedRoot,
			Reason:      "leaf cert missing Android Key Attestation extension",
		}, nil
	}

	parsed, err := parseKeyDescription(extBytes)
	if err != nil {
		return Verdict{}, fmt.Errorf("parse attestation extension: %w", err)
	}

	// Compose the final verdict. Honest framing: Verified=true requires
	// trustedRoot=true; a structurally-valid leaf with an unknown root
	// is reported as Verified=false even though we parsed every field.
	verdict := Verdict{
		Verified:       trustedRoot,
		SecurityLevel:  securityLevelString(parsed.securityLevel),
		HardwareBacked: parsed.securityLevel == akaSecurityLevelTrustedEnvironment || parsed.securityLevel == akaSecurityLevelStrongBox,
		TrustedRoot:    trustedRoot,
	}
	if parsed.rootOfTrustPresent {
		verdict.VerifiedBootState = verifiedBootStateString(parsed.verifiedBootState)
		verdict.DeviceLocked = parsed.deviceLocked
	}
	if trustedRoot {
		verdict.Reason = "chain verified against bundled Google AKA roots"
	} else {
		verdict.Reason = "chain does not anchor at a known Google AKA root: " + verifyErr.Error()
	}
	return verdict, nil
}

// parseLengthPrefixedChain decodes a sequence of DER-encoded X.509
// certificates from a concatenated length-prefixed stream.
//
// Wire format: for each cert,
//
//	uint16-be length || that many bytes of DER
//
// Repeated until the input is exhausted. The first cert is the leaf,
// each subsequent cert is its issuer (the standard attestation
// chain ordering). Chosen instead of bare concatenated DER because
// it lets us bound each cert's read without re-parsing the ASN.1
// length prefix.
func parseLengthPrefixedChain(raw []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	pos := 0
	for pos < len(raw) {
		if pos+2 > len(raw) {
			return nil, fmt.Errorf("truncated length prefix at offset %d", pos)
		}
		certLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		if pos+certLen > len(raw) {
			return nil, fmt.Errorf("truncated cert at offset %d (declared %d bytes, %d remaining)",
				pos, certLen, len(raw)-pos)
		}
		cert, err := x509.ParseCertificate(raw[pos : pos+certLen])
		if err != nil {
			return nil, fmt.Errorf("parse cert %d: %w", len(chain), err)
		}
		chain = append(chain, cert)
		pos += certLen
	}
	return chain, nil
}

// keyDescription is the ASN.1 SEQUENCE Google embeds in the leaf
// cert's attestation extension. We decode the whole thing in one
// pass; the AuthorizationList fields stay as RawValue so we can walk
// them manually for the RootOfTrust we care about (parsing the full
// AuthorizationList shape would be ~50 optional context-tagged fields
// that we don't otherwise use).
//
// Per Android docs:
// https://source.android.com/docs/security/features/keystore/attestation
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion         INTEGER,
//	    attestationSecurityLevel   ENUMERATED,
//	    keymasterVersion           INTEGER,
//	    keymasterSecurityLevel     ENUMERATED,
//	    attestationChallenge       OCTET STRING,
//	    uniqueId                   OCTET STRING,
//	    softwareEnforced           AuthorizationList,
//	    teeEnforced                AuthorizationList,
//	}
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// rootOfTrust mirrors the RootOfTrust SEQUENCE nested inside an
// AuthorizationList under context tag [704]. We treat VerifiedBootHash
// as optional because KM3 and older devices don't emit it.
//
//	RootOfTrust ::= SEQUENCE {
//	    verifiedBootKey            OCTET STRING,
//	    deviceLocked               BOOLEAN,
//	    verifiedBootState          ENUMERATED,
//	    verifiedBootHash           OCTET STRING OPTIONAL,
//	}
type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

// authorizationListRootOfTrustTag is the context-specific tag Google
// reserves for RootOfTrust inside an AuthorizationList. Encoded as
// [704] EXPLICIT in the schema; on the wire that's a constructed
// context-tagged element whose body is the wrapped RootOfTrust
// SEQUENCE.
const authorizationListRootOfTrustTag = 704

// Verified-boot state ENUMERATED values, per the schema. The "Verified"
// state means the bootloader is locked AND the running OS image is
// signed by the device manufacturer's published key. Everything else
// is some form of compromise from the attestation policy's standpoint.
const (
	verifiedBootStateVerified   = 0
	verifiedBootStateSelfSigned = 1
	verifiedBootStateUnverified = 2
	verifiedBootStateFailed     = 3
)

// akaParsed is what parseKeyDescription returns: the structured signals
// the verifier surfaces in the Verdict. Fields are zero-valued when
// absent (e.g. older attestations without RootOfTrust); the
// rootOfTrustPresent flag distinguishes "absent" from "verified state
// 0 (= Verified)" so the policy layer can refuse hand-wave-trust an
// attestation that didn't carry the gate-relevant bits at all.
type akaParsed struct {
	securityLevel       int
	rootOfTrustPresent  bool
	verifiedBootState   int
	deviceLocked        bool
}

// parseKeyDescription decodes the full KeyDescription SEQUENCE, then
// walks teeEnforced looking for the [704] EXPLICIT RootOfTrust. Returns
// an akaParsed with the security level, plus the verified-boot signals
// when present.
//
// Why teeEnforced and not softwareEnforced: softwareEnforced is what
// the OS claims; teeEnforced is what the TEE/StrongBox observed during
// attestation-key generation and is cryptographically signed by the
// hardware. For a hardware-backed key (the only case
// `requireHardwareBacked: true` lets through), the gate-relevant
// RootOfTrust lives in teeEnforced.
func parseKeyDescription(extBytes []byte) (akaParsed, error) {
	var kd keyDescription
	rest, err := asn1.Unmarshal(extBytes, &kd)
	if err != nil {
		return akaParsed{}, fmt.Errorf("unmarshal KeyDescription: %w", err)
	}
	if len(rest) != 0 {
		return akaParsed{}, errors.New("trailing bytes after KeyDescription")
	}

	parsed := akaParsed{
		securityLevel: int(kd.AttestationSecurityLevel),
	}

	rot, hasRoT, err := findRootOfTrust(kd.TeeEnforced)
	if err != nil {
		return akaParsed{}, fmt.Errorf("walk teeEnforced: %w", err)
	}
	if hasRoT {
		parsed.rootOfTrustPresent = true
		parsed.verifiedBootState = int(rot.VerifiedBootState)
		parsed.deviceLocked = rot.DeviceLocked
	}
	return parsed, nil
}

// findRootOfTrust iterates an AuthorizationList's body looking for the
// context-tagged [704] EXPLICIT RootOfTrust. Returns (zero, false,
// nil) when the tag is absent (legitimate for older attestations).
//
// Robust to AuthorizationList's many other context-tagged fields:
// we skip past any tag we don't recognize without descending into it.
func findRootOfTrust(authList asn1.RawValue) (rootOfTrust, bool, error) {
	if authList.Tag != asn1.TagSequence || authList.Class != asn1.ClassUniversal {
		// teeEnforced may be empty (encoded as an empty SEQUENCE) or
		// missing entirely on really old Keymaster versions. Treat
		// either as "no RootOfTrust" rather than an error — the
		// policy layer surfaces that absence via rootOfTrustPresent.
		if authList.FullBytes == nil {
			return rootOfTrust{}, false, nil
		}
		return rootOfTrust{}, false, fmt.Errorf(
			"expected AuthorizationList SEQUENCE, got tag=%d class=%d",
			authList.Tag, authList.Class)
	}

	body := authList.Bytes
	for len(body) > 0 {
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(body, &elem)
		if err != nil {
			return rootOfTrust{}, false, fmt.Errorf("iterate AuthorizationList: %w", err)
		}
		body = next
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != authorizationListRootOfTrustTag {
			continue
		}
		// EXPLICIT wrap: elem.Bytes contains the full DER of the
		// inner RootOfTrust SEQUENCE (tag + length + content).
		var rot rootOfTrust
		if _, err := asn1.Unmarshal(elem.Bytes, &rot); err != nil {
			return rootOfTrust{}, false, fmt.Errorf("decode RootOfTrust: %w", err)
		}
		return rot, true, nil
	}
	return rootOfTrust{}, false, nil
}

func securityLevelString(level int) string {
	switch level {
	case akaSecurityLevelSoftware:
		return "software"
	case akaSecurityLevelTrustedEnvironment:
		return "tee"
	case akaSecurityLevelStrongBox:
		return "strongbox"
	default:
		return fmt.Sprintf("unknown(%d)", level)
	}
}

// verifiedBootStateString maps the wire enum to the human-readable
// string the Verdict carries. "verified" is the only state that
// implies "boot was signed by the device-manufacturer key"; the
// other states each represent a different degree of operator
// customization, none of which we want to trust by default.
func verifiedBootStateString(state int) string {
	switch state {
	case verifiedBootStateVerified:
		return "verified"
	case verifiedBootStateSelfSigned:
		return "self-signed"
	case verifiedBootStateUnverified:
		return "unverified"
	case verifiedBootStateFailed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}
