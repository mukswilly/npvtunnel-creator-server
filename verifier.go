package main

import (
	"crypto/x509"
	"fmt"
)

// AttestationVerifier is the plug-in interface for verifying the
// attestation evidence a recipient sends in IssueRequest.attestation.token.
//
// One policy mode gates on "claimed attestation"
// (platform != NONE, non-empty token). That's a sentinel signal — a
// junk token passes. The verifier layer exists so the
// policy can gate on a real verdict.
//
// Each platform-specific implementation lives next to its tag string
// in the verifierRegistry. The AttestationPolicy.Verifier field names
// which one runs (empty = none; behavior falls back to the
// claimed-only check).
//
// Verifier instances should be cheap to construct and free of per-
// request state. The same verifier is shared across all requests.
type AttestationVerifier interface {
	// Verify decodes blob.Token, runs whatever cryptographic checks the
	// implementation can perform, and returns a structured Verdict.
	//
	// Returning an error means the verifier could not produce a
	// verdict at all (malformed input). A successful return with
	// Verdict.Verified = false means the input was well-formed but
	// failed verification.
	Verify(blob AttestationBlob) (Verdict, error)
}

// Verdict is the structured outcome of an attestation verification.
type Verdict struct {
	// Verified reports whether the verifier accepts the token. False
	// means the policy should treat this client as unattested.
	Verified bool

	// SecurityLevel is the attested key-storage tier:
	//   "software"   — software-only crypto, no TEE.
	//   "tee"        — Trusted Execution Environment (ARM TrustZone, etc.).
	//   "strongbox"  — dedicated security chip (Pixel Titan M, similar).
	//   ""           — unknown / verifier didn't extract it.
	SecurityLevel string

	// HardwareBacked is true when SecurityLevel is "tee" or "strongbox".
	// A convenience derived from SecurityLevel; the policy enforces
	// against this when AttestationPolicy.RequireHardwareBacked is set.
	HardwareBacked bool

	// TrustedRoot reports whether the verifier verified the attestation
	// chain up to a known platform-vendor root (Google for AKA, Apple
	// for App Attest). False when chain verification wasn't performed,
	// didn't complete, or the chain's terminal cert isn't in the
	// trusted-roots pool.
	//
	// For AKA, the verifier anchors verification at Google's published
	// hardware-attestation roots, bundled in aka_roots.go. A chain
	// terminating at a self-signed cert (or any non-Google root) gets
	// TrustedRoot=false and the policy layer can refuse it via
	// AttestationPolicy.RequireTrustedRoot.
	//
	// Known limit: Google publishes a revocation list at
	// https://android.googleapis.com/attestation/status. A cert Google
	// has marked revoked for known hardware compromise still produces
	// TrustedRoot=true here. A fetch-and-cache revocation gate was built
	// and then removed (fail-open, lagged real compromise, and useless
	// against the rooted-recipient threat that extracts inside the
	// credential TTL) — see aka.go's "What it does NOT verify".
	TrustedRoot bool

	// VerifiedBootState is the bootloader/verified-boot state reported
	// by the device's TEE in the attestation extension's RootOfTrust
	// field. Empty when the verifier didn't extract it (no
	// RootOfTrust on this attestation, or non-AKA verifier).
	//
	// Wire values per Android docs:
	//   "verified"    — bootloader locked, OS signed by device-
	//                   manufacturer key. The only state that gives a
	//                   meaningful guarantee against on-device
	//                   tampering.
	//   "self-signed" — bootloader locked, but with a user-installed
	//                   root key. The device owner can verify what
	//                   they signed; the creator can't.
	//   "unverified"  — bootloader unlocked. Root-friendly state;
	//                   anything in the running OS could have been
	//                   patched.
	//   "failed"      — boot verification ran and failed. Hardware
	//                   says something is wrong; trust nothing.
	//
	// policy.requireVerifiedBoot gates on state ==
	// "verified" AND DeviceLocked == true, which is the
	// cryptographically-meaningful "this is a real OEM-shipped phone
	// running an unmodified OS" assertion.
	VerifiedBootState string

	// DeviceLocked reports whether the bootloader was locked at the
	// time of attestation, per the same RootOfTrust field. Combined
	// with VerifiedBootState to enforce requireVerifiedBoot.
	//
	// False when the verifier didn't extract a RootOfTrust at all.
	// The policy layer treats "absent RootOfTrust" as "not locked" —
	// a creator who's strict about boot state should refuse
	// attestations that don't carry the gate-relevant signal.
	DeviceLocked bool

	// Reason is a short, log-safe human-readable explanation of the
	// verdict. Surfaced in audit records and (optionally) in error
	// responses.
	Reason string
}

// verifierRegistry maps the AttestationPolicy.Verifier name to a
// verifier instance. An empty name resolves to no verifier (Lookup
// returns nil, nil) and the policy layer falls back to the claimed-
// attestation check; an unknown name is a load-time error, surfaced
// when configs.json is validated. The registry never decides accept/
// reject — it only produces the verdict the policy layer acts on.
type verifierRegistry struct {
	verifiers map[string]AttestationVerifier
}

// newVerifierRegistry returns the default registry: AKA anchored at
// the bundled Google roots + App Attest anchored at the bundled
// Apple root. A failure to load either bundled file is a build-time
// bug (corrupted PEM, empty file) — we panic rather than silently
// produce a verifier with no trust anchor, which would reject every
// legitimate chain in a way that's hard for an operator to
// diagnose.
func newVerifierRegistry() *verifierRegistry {
	akaRoots, err := loadGoogleAkaRoots()
	if err != nil {
		panic("load embedded Google AKA roots: " + err.Error())
	}
	appAttestRoots, err := loadAppleAppAttestRoots()
	if err != nil {
		panic("load embedded Apple App Attest roots: " + err.Error())
	}
	akaVerifier := newAndroidKeyAttestationVerifier(akaRoots)
	return &verifierRegistry{
		verifiers: map[string]AttestationVerifier{
			"android-key-attestation": akaVerifier,
			"apple-app-attest":        newAppleAppAttestVerifier(appAttestRoots),
		},
	}
}

// newVerifierRegistryWithRoots is the test-injection seam: build a
// registry whose AKA verifier anchors at the given pool. Other
// verifiers (App Attest) use a separate injection helper —
// newVerifierRegistryWithAppAttestRoots — when those need a
// synthetic root.
func newVerifierRegistryWithRoots(roots *x509.CertPool) *verifierRegistry {
	return &verifierRegistry{
		verifiers: map[string]AttestationVerifier{
			"android-key-attestation": newAndroidKeyAttestationVerifier(roots),
		},
	}
}

// newVerifierRegistryWithAppAttestRoots builds a registry whose
// App Attest verifier anchors at the given pool. Used by the
// app_attest_test.go integration tests to swap in synthetic roots.
func newVerifierRegistryWithAppAttestRoots(roots *x509.CertPool) *verifierRegistry {
	return &verifierRegistry{
		verifiers: map[string]AttestationVerifier{
			"apple-app-attest": newAppleAppAttestVerifier(roots),
		},
	}
}

// Lookup returns the verifier for name, or nil + error if name is
// non-empty but not registered. Empty name returns (nil, nil) — the
// caller treats nil verifier as "no verification configured."
func (r *verifierRegistry) Lookup(name string) (AttestationVerifier, error) {
	if name == "" {
		return nil, nil
	}
	v, ok := r.verifiers[name]
	if !ok {
		return nil, fmt.Errorf("unknown verifier %q (known: %v)", name, r.knownNames())
	}
	return v, nil
}

func (r *verifierRegistry) knownNames() []string {
	out := make([]string, 0, len(r.verifiers))
	for k := range r.verifiers {
		out = append(out, k)
	}
	return out
}
