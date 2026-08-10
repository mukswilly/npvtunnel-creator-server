package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// androidKeyAttestationOID is the object identifier of the X.509 extension that
// carries the hardware key-attestation KeyDescription in the leaf certificate.
var androidKeyAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Security levels reported by the attestation extension, indicating where the
// attested key and its attestation are enforced: in software, in a trusted
// execution environment, or in a dedicated secure element (StrongBox).
const (
	akaSecurityLevelSoftware           = 0
	akaSecurityLevelTrustedEnvironment = 1
	akaSecurityLevelStrongBox          = 2
)

// androidKeyAttestationVerifier validates a hardware key-attestation certificate
// chain against a fixed pool of trusted root certificates and extracts the
// attestation verdict from the leaf certificate's attestation extension.
type androidKeyAttestationVerifier struct {
	roots *x509.CertPool
}

// newAndroidKeyAttestationVerifier returns a verifier that anchors chains at the
// supplied pool of trusted roots.
func newAndroidKeyAttestationVerifier(roots *x509.CertPool) *androidKeyAttestationVerifier {
	return &androidKeyAttestationVerifier{roots: roots}
}

// Verify decodes and validates the attestation token in blob and returns a
// Verdict describing the attested key. The token is a base64url-encoded,
// length-prefixed X.509 certificate chain. Verification checks that each
// certificate is signed by the next and that the chain anchors at one of the
// configured trusted roots, then reads the security properties from the leaf
// certificate's attestation extension.
//
// A returned error indicates the token was malformed and could not be evaluated.
// A well-formed token that fails validation yields a Verdict with Verified set
// to false and Reason explaining why; the error is nil in that case.
func (v *androidKeyAttestationVerifier) Verify(blob AttestationBlob) (Verdict, error) {
	if blob.Platform != "ANDROID" { // only the Android attestation format is handled
		return Verdict{Verified: false, Reason: "non-Android platform"}, nil
	}
	if blob.Token == "" {
		return Verdict{Verified: false, Reason: "empty token"}, nil
	}
	if v.roots == nil {

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

	// The chain is ordered leaf-first: each certificate must be signed by the
	// one that follows it. Reject the chain if any link's signature is invalid.
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

	// Build a standard path-validation request: the first certificate is the
	// leaf and the remainder act as intermediates anchored at the trusted roots.
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,

		// Attestation leaf certificates do not carry a conventional key-usage
		// purpose, so accept any extended key usage during path validation.
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: time.Now(),
	}

	// trustedRoot records whether the chain validates to a trusted root. Path
	// validation failing is not fatal: the verdict still reports the attested
	// properties below, just flagged as untrusted.
	_, verifyErr := leaf.Verify(verifyOpts)
	trustedRoot := verifyErr == nil

	// Locate the attestation extension on the leaf certificate by its OID.
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

	// Assemble the verdict. The key is considered hardware-backed when its
	// attestation security level is the trusted environment or StrongBox.
	verdict := Verdict{
		Verified:       trustedRoot,
		SecurityLevel:  securityLevelString(parsed.securityLevel),
		HardwareBacked: parsed.securityLevel == akaSecurityLevelTrustedEnvironment || parsed.securityLevel == akaSecurityLevelStrongBox,
		TrustedRoot:    trustedRoot,
	}
	if parsed.rootOfTrustPresent { // boot-state fields are set only when a RootOfTrust was present
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

// parseLengthPrefixedChain decodes a certificate chain serialized as a sequence
// of records, each a two-byte big-endian length followed by that many bytes of
// DER-encoded certificate. Certificates are returned in the order they appear.
func parseLengthPrefixedChain(raw []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	pos := 0
	for pos < len(raw) {
		if pos+2 > len(raw) { // each record begins with a two-byte big-endian length prefix
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

// keyDescription describes the layout of the top-level KeyDescription SEQUENCE
// encoded in the attestation extension. The two enforcement lists are kept as
// raw ASN.1 so their context-tagged authorization entries can be walked on
// demand: SoftwareEnforced holds entries enforced outside secure hardware and
// TeeEnforced holds those enforced by secure hardware.
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

// rootOfTrust describes the layout of the RootOfTrust SEQUENCE found within an
// authorization list. It reports the device's boot integrity: whether the
// bootloader is locked and the verified-boot state, plus the boot key and
// (optionally) the boot hash.
type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

// authorizationListRootOfTrustTag is the context-specific tag number under which
// the RootOfTrust entry appears inside an authorization list.
const authorizationListRootOfTrustTag = 704

// Verified-boot states reported by a RootOfTrust, describing the trust in the
// software the device booted: a verified chain, a self-signed (user) key, an
// unverified state, or a failed verification.
const (
	verifiedBootStateVerified   = 0
	verifiedBootStateSelfSigned = 1
	verifiedBootStateUnverified = 2
	verifiedBootStateFailed     = 3
)

// akaParsed holds the subset of attestation fields extracted from the extension:
// the attestation security level and, when a RootOfTrust was present, the
// verified-boot state and bootloader-lock flag.
type akaParsed struct {
	securityLevel      int
	rootOfTrustPresent bool
	verifiedBootState  int
	deviceLocked       bool
}

// parseKeyDescription unmarshals the attestation extension's KeyDescription and
// extracts the security level and, if a RootOfTrust entry is present in the
// hardware-enforced authorization list, the verified-boot state and lock flag.
func parseKeyDescription(extBytes []byte) (akaParsed, error) {
	var kd keyDescription
	rest, err := asn1.Unmarshal(extBytes, &kd)
	if err != nil {
		return akaParsed{}, fmt.Errorf("unmarshal KeyDescription: %w", err)
	}
	if len(rest) != 0 { // the extension must contain exactly one KeyDescription and nothing more
		return akaParsed{}, errors.New("trailing bytes after KeyDescription")
	}

	parsed := akaParsed{
		securityLevel: int(kd.AttestationSecurityLevel),
	}

	// The RootOfTrust lives in the hardware-enforced authorization list.
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

// findRootOfTrust scans an authorization list for its RootOfTrust entry. The
// list is a SEQUENCE of context-tagged elements; the function iterates them and
// decodes the one carrying authorizationListRootOfTrustTag. It reports whether
// such an entry was found. An empty (absent) authorization list yields no entry
// and no error; a value that is not a SEQUENCE is an error.
func findRootOfTrust(authList asn1.RawValue) (rootOfTrust, bool, error) {
	if authList.Tag != asn1.TagSequence || authList.Class != asn1.ClassUniversal {

		// An entirely absent authorization list is acceptable; only a present
		// value of the wrong shape is an error.
		if authList.FullBytes == nil {
			return rootOfTrust{}, false, nil
		}
		return rootOfTrust{}, false, fmt.Errorf(
			"expected AuthorizationList SEQUENCE, got tag=%d class=%d",
			authList.Tag, authList.Class)
	}

	// Walk the elements of the SEQUENCE one at a time, advancing through the body.
	body := authList.Bytes
	for len(body) > 0 {
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(body, &elem)
		if err != nil {
			return rootOfTrust{}, false, fmt.Errorf("iterate AuthorizationList: %w", err)
		}
		body = next
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != authorizationListRootOfTrustTag {
			continue // skip entries other than the context-tagged RootOfTrust
		}

		// Decode the inner RootOfTrust SEQUENCE from the tagged element's content.
		var rot rootOfTrust
		if _, err := asn1.Unmarshal(elem.Bytes, &rot); err != nil {
			return rootOfTrust{}, false, fmt.Errorf("decode RootOfTrust: %w", err)
		}
		return rot, true, nil
	}
	return rootOfTrust{}, false, nil
}

// securityLevelString renders an attestation security level as a short label,
// falling back to an "unknown(n)" form for unrecognized values.
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

// verifiedBootStateString renders a verified-boot state as a short label,
// falling back to an "unknown(n)" form for unrecognized values.
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
