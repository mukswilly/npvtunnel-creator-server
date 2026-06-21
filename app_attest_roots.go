package main

import (
	"crypto/x509"
	_ "embed"
)

// Apple's App Attestation root, embedded at build time so a fresh
// creator-server deployment can verify App Attest chains the day the
// operator runs the binary.
//
// Same rationale as the AKA roots (the no-creator-burden rationale):
// the operator doesn't fetch or place root certs; they ship
// inside the binary. Apple's root has 25-year validity and rotates on
// year-plus timescales, so compiled-in is the right granularity.
//
// To refresh: re-fetch from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem,
// replace attestation-roots/apple-app-attest-root.pem, and rebuild.
//
//go:embed attestation-roots/apple-app-attest-root.pem
var appleAppAttestRootPEM []byte

// loadAppleAppAttestRoots parses the embedded PEM bundle into an
// *x509.CertPool. Called once at verifier-registry construction.
// Shares the parseRootsPEM primitive with the AKA loader for
// uniform error handling.
func loadAppleAppAttestRoots() (*x509.CertPool, error) {
	return parseRootsPEM(appleAppAttestRootPEM)
}
