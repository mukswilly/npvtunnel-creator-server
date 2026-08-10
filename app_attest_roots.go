package main

import (
	"crypto/x509"
	_ "embed"
)

// appleAppAttestRootPEM is the PEM-encoded App Attest root certificate,
// embedded at build time and used to anchor attestation certificate chains.
//
//go:embed attestation-roots/apple-app-attest-root.pem
var appleAppAttestRootPEM []byte

// loadAppleAppAttestRoots parses the embedded root PEM into a certificate pool.
func loadAppleAppAttestRoots() (*x509.CertPool, error) {
	return parseRootsPEM(appleAppAttestRootPEM)
}
