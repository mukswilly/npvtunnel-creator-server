package main

import (
	_ "embed"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Google's Android Key Attestation root certificates, embedded at build
// time so a fresh creator-server deployment can verify hardware
// attestation chains the day the operator runs the binary.
//
// Honors principles.md §1 — "no creator burden": the operator doesn't
// fetch or place root certs; they ship inside the binary. The roots are
// public (https://android.googleapis.com/attestation/root) and rotate on
// year-plus timescales, so compiled-in is the right granularity.
//
// To refresh: re-fetch from the URL above, replace the file content, and
// rebuild. See attestation-roots/google-aka-roots.pem for the provenance
// comment and current cert summary.
//
//go:embed attestation-roots/google-aka-roots.pem
var googleAkaRootsPEM []byte

// loadGoogleAkaRoots parses the embedded PEM bundle into an
// *x509.CertPool. Called once at verifier-registry construction.
//
// Returns an error if the bundle is empty or contains no parseable
// certs — that would be a build-time mistake (somebody truncated or
// corrupted the file), and we want it to surface loudly rather than
// silently produce a verifier that trusts nothing.
func loadGoogleAkaRoots() (*x509.CertPool, error) {
	return parseRootsPEM(googleAkaRootsPEM)
}

// parseRootsPEM is the parsing primitive, exposed separately from
// loadGoogleAkaRoots so tests can build alternate pools (e.g. a pool
// containing a synthetic test root) without touching the embed.
func parseRootsPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := pemBytes
	count := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			// pem.Decode returns nil when it can't find another PEM
			// block. Any remaining bytes are non-PEM noise (file
			// trailer / comments) — fine to stop here.
			break
		}
		if block.Type != "CERTIFICATE" {
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
