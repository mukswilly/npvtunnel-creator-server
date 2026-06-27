package main

import (
	"crypto/x509"
	"fmt"
)

// AttestationVerifier validates an attestation blob and reports a Verdict.
// Each named implementation handles one attestation format.
type AttestationVerifier interface {
	Verify(blob AttestationBlob) (Verdict, error)
}

// Verdict is the result of verifying an attestation blob. A policy combines
// these fields to decide whether a request counts as attested.
type Verdict struct {
	// Verified reports whether the attestation passed the verifier's checks.
	Verified bool

	// SecurityLevel is the verifier-reported strength of the attesting key.
	SecurityLevel string

	// HardwareBacked reports whether the attesting key is held in secure hardware.
	HardwareBacked bool

	// TrustedRoot reports whether the certificate chain anchors at a known root.
	TrustedRoot bool

	// VerifiedBootState is the reported boot-integrity state of the device.
	VerifiedBootState string

	// DeviceLocked reports whether the device bootloader is locked.
	DeviceLocked bool

	// Reason explains the verdict, primarily when verification fails.
	Reason string
}

// verifierRegistry maps a verifier name to its implementation, letting a
// policy select a verifier by name.
type verifierRegistry struct {
	verifiers map[string]AttestationVerifier
}

// newVerifierRegistry builds a registry with every supported verifier, loading
// each verifier's embedded trust roots. It panics if a root set fails to load.
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

// newVerifierRegistryWithRoots builds a registry holding only the
// android-key-attestation verifier, anchored at the supplied roots.
func newVerifierRegistryWithRoots(roots *x509.CertPool) *verifierRegistry {
	return &verifierRegistry{
		verifiers: map[string]AttestationVerifier{
			"android-key-attestation": newAndroidKeyAttestationVerifier(roots),
		},
	}
}

// newVerifierRegistryWithAppAttestRoots builds a registry holding only the
// apple-app-attest verifier, anchored at the supplied roots.
func newVerifierRegistryWithAppAttestRoots(roots *x509.CertPool) *verifierRegistry {
	return &verifierRegistry{
		verifiers: map[string]AttestationVerifier{
			"apple-app-attest": newAppleAppAttestVerifier(roots),
		},
	}
}

// Lookup resolves a verifier by name. An empty name yields a nil verifier and
// no error, meaning no verifier is configured. An unknown name is an error.
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

// knownNames returns the registered verifier names, used in lookup errors.
func (r *verifierRegistry) knownNames() []string {
	out := make([]string, 0, len(r.verifiers))
	for k := range r.verifiers {
		out = append(out, k)
	}
	return out
}
