package main

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// googleAkaRootsPEM holds the PEM-encoded trusted root certificates, embedded
// into the binary at build time, that attestation chains are anchored to.
//
//go:embed attestation-roots/google-aka-roots.pem
var googleAkaRootsPEM []byte

// loadGoogleAkaRoots parses the embedded roots PEM into a certificate pool for
// use as the trust anchor when verifying attestation chains.
func loadGoogleAkaRoots() (*x509.CertPool, error) {
	return parseRootsPEM(googleAkaRootsPEM)
}

// parseRootsPEM decodes every CERTIFICATE block in a PEM byte slice and adds it
// to a fresh certificate pool. Non-certificate blocks are skipped. It returns an
// error if a certificate fails to parse or if the input contains none.
func parseRootsPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := pemBytes
	count := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil { // no further PEM block could be decoded

			break
		}
		if block.Type != "CERTIFICATE" { // ignore any non-certificate PEM blocks
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse root cert %d: %w", count, err)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in roots PEM")
	}
	return pool, nil
}
