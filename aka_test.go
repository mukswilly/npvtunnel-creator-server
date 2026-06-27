package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Android verifier returns an unverified verdict for a non-ANDROID platform.
func TestAkaVerifierRejectsNonAndroid(t *testing.T) {
	v := newTrustingVerifier(t, akaSecurityLevelStrongBox)
	verdict, err := v.Verify(AttestationBlob{Platform: "IOS", Token: "tok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("non-Android platform must not be verified by AKA")
	}
}

// An empty token yields an unverified verdict without erroring.
func TestAkaVerifierRejectsEmptyToken(t *testing.T) {
	v := newTrustingVerifier(t, akaSecurityLevelStrongBox)
	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("empty token must not verify")
	}
}

// A token that is not valid base64url surfaces as a decode error.
func TestAkaVerifierRejectsMalformedBase64(t *testing.T) {
	v := newTrustingVerifier(t, akaSecurityLevelStrongBox)
	_, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: "!!!"})
	if err == nil {
		t.Fatalf("expected error on malformed base64")
	}
}

// With no trust roots configured the verifier fails closed even on a well-formed chain.
func TestAkaVerifierWithNoRootsFailsClosed(t *testing.T) {
	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(nil)
	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified || verdict.TrustedRoot {
		t.Fatalf("verifier with nil roots must fail closed, got %+v", verdict)
	}
}

// A chain anchored at a trusted root verifies, and the StrongBox security level
// is reported as hardware-backed.
func TestAkaVerifierAcceptsTrustedSynthChain(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("trusted-root synth chain should verify, got %+v", verdict)
	}
	if !verdict.TrustedRoot {
		t.Errorf("TrustedRoot must be true when the chain anchors at a trusted root")
	}
	if verdict.SecurityLevel != "strongbox" {
		t.Errorf("SecurityLevel = %q, want strongbox", verdict.SecurityLevel)
	}
	if !verdict.HardwareBacked {
		t.Errorf("StrongBox should be HardwareBacked")
	}
}

// A chain whose root is not in the pool is not Verified, but the security level
// is still parsed out of the leaf extension.
func TestAkaVerifierRejectsUntrustedRoot(t *testing.T) {
	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)

	// Seed the pool from a second, unrelated chain so the first chain cannot anchor.
	_, _, otherRoot := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, otherRoot))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("chain with untrusted root must NOT be Verified, got %+v", verdict)
	}
	if verdict.TrustedRoot {
		t.Errorf("TrustedRoot must be false for an unknown root")
	}

	if verdict.SecurityLevel != "strongbox" {
		t.Errorf("SecurityLevel should still be extracted, got %q", verdict.SecurityLevel)
	}
}

// A TEE-level attestation is reported as "tee" and hardware-backed.
func TestAkaVerifierExtractsTeeLevel(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelTrustedEnvironment)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.SecurityLevel != "tee" {
		t.Errorf("SecurityLevel = %q, want tee", verdict.SecurityLevel)
	}
	if !verdict.HardwareBacked {
		t.Errorf("TEE level should be HardwareBacked")
	}
}

// A software-level attestation is reported as "software" and not hardware-backed.
func TestAkaVerifierExtractsSoftwareLevel(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelSoftware)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.SecurityLevel != "software" {
		t.Errorf("SecurityLevel = %q, want software", verdict.SecurityLevel)
	}
	if verdict.HardwareBacked {
		t.Errorf("software level should NOT be HardwareBacked")
	}
}

// A leaf lacking the attestation extension does not verify and the reason names it.
func TestAkaVerifierRejectsLeafWithoutExtension(t *testing.T) {
	chain, root := buildChainWithoutAkaExtension(t)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("chain without AKA extension should not verify")
	}
	if !strings.Contains(verdict.Reason, "Attestation extension") {
		t.Errorf("reason = %q, expected 'Attestation extension' mention", verdict.Reason)
	}
}

// A RootOfTrust with verified boot and a locked bootloader is surfaced in the verdict.
func TestAkaVerifierExtractsVerifiedBootStateAndDeviceLocked(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRootWithBoot(
		t, akaSecurityLevelStrongBox, verifiedBootRoT(),
	)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.VerifiedBootState != "verified" {
		t.Errorf("VerifiedBootState = %q, want verified", verdict.VerifiedBootState)
	}
	if !verdict.DeviceLocked {
		t.Errorf("DeviceLocked = false, want true")
	}
}

// An unverified boot state is surfaced but does not by itself fail chain verification;
// enforcing it is left to policy.
func TestAkaVerifierExtractsUnverifiedBootState(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRootWithBoot(
		t, akaSecurityLevelStrongBox, unverifiedBootRoT(),
	)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("verifier must still report Verified=true on chain anchor success; unverified-boot is a policy concern, got %+v", verdict)
	}
	if verdict.VerifiedBootState != "unverified" {
		t.Errorf("VerifiedBootState = %q, want unverified", verdict.VerifiedBootState)
	}
	if verdict.DeviceLocked {
		t.Errorf("DeviceLocked = true, want false")
	}
}

// When the extension carries no RootOfTrust, the chain still verifies and the
// boot fields stay empty/false.
func TestAkaVerifierAttestationWithoutRootOfTrust(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("chain without RoT should still verify (chain itself is fine), got %+v", verdict)
	}
	if verdict.VerifiedBootState != "" {
		t.Errorf("VerifiedBootState = %q, want empty string for absent RootOfTrust", verdict.VerifiedBootState)
	}
	if verdict.DeviceLocked {
		t.Errorf("DeviceLocked must be false when RoT is absent")
	}
}

// End to end: with requireVerifiedBoot set, a verified-boot locked device is admitted.
func TestIssueRequireVerifiedBootAcceptsVerifiedDevice(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true,
			"requireVerifiedBoot": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRootWithBoot(t, akaSecurityLevelStrongBox, verifiedBootRoT())
	// Point the verifier at the synthetic root so the test chain anchors.
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for verified+locked device, got %d: %s", resp.StatusCode, respBytes)
	}
}

// End to end: with requireVerifiedBoot set, an unverified-boot device is rejected.
func TestIssueRequireVerifiedBootRejectsUnverifiedDevice(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true,
			"requireVerifiedBoot": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRootWithBoot(t, akaSecurityLevelStrongBox, unverifiedBootRoT())
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 (verified-boot required), got %d: %s", resp.StatusCode, respBytes)
	}
}

// End to end: requireVerifiedBoot rejects an attestation that omits a RootOfTrust
// entirely, since boot state then cannot be proven.
func TestIssueRequireVerifiedBootRejectsAttestationWithoutRootOfTrust(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true,
			"requireVerifiedBoot": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 (no RoT in attestation), got %d: %s", resp.StatusCode, respBytes)
	}
}

// The embedded production roots load, and a synthetic chain must not anchor at them.
func TestAkaProductionRootsLoad(t *testing.T) {
	pool, err := loadGoogleAkaRoots()
	if err != nil {
		t.Fatalf("loadGoogleAkaRoots: %v", err)
	}
	if pool == nil {
		t.Fatalf("nil pool from embedded bundle")
	}

	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(pool)
	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified || verdict.TrustedRoot {
		t.Fatalf("synth chain must not anchor at the production Google roots, got %+v", verdict)
	}
}

// A registered verifier name resolves to a non-nil verifier.
func TestVerifierRegistryLookupKnown(t *testing.T) {
	r := newVerifierRegistry()
	v, err := r.Lookup("android-key-attestation")
	if err != nil {
		t.Fatalf("known verifier should resolve: %v", err)
	}
	if v == nil {
		t.Fatalf("registry returned nil for known name")
	}
}

// An unrecognized verifier name is an error.
func TestVerifierRegistryRejectsUnknown(t *testing.T) {
	r := newVerifierRegistry()
	_, err := r.Lookup("from-the-future")
	if err == nil {
		t.Fatalf("unknown verifier name must be rejected")
	}
}

// An empty verifier name resolves to (nil, nil), meaning "no verifier".
func TestVerifierRegistryEmptyNameReturnsNil(t *testing.T) {
	r := newVerifierRegistry()
	v, err := r.Lookup("")
	if err != nil {
		t.Fatalf("empty name should return (nil, nil), got err %v", err)
	}
	if v != nil {
		t.Fatalf("empty name should return nil verifier")
	}
}

// A config naming a verifier the registry does not know fails to load.
func TestConfigsFileRejectsUnknownVerifier(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {"mode": "soft", "verifier": "android-key-attest"}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatalf("expected error on unknown verifier")
	}
}

// End to end: requireHardwareBacked rejects a software-level attestation.
func TestIssueStrictWithVerifierRejectsSoftwareKey(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelSoftware)
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 (hardware required), got %d: %s", resp.StatusCode, respBytes)
	}
}

// End to end: requireHardwareBacked admits a StrongBox attestation.
func TestIssueStrictWithVerifierAcceptsStrongBox(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for StrongBox attestation, got %d: %s", resp.StatusCode, respBytes)
	}
}

// End to end: requireTrustedRoot rejects a chain that does not anchor at a
// configured root.
func TestIssueRequireTrustedRootRejectsUntrustedRoot(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	// Leave the default production roots in place; the synthetic root is not among them.
	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 (untrusted root), got %d: %s", resp.StatusCode, respBytes)
	}
}

// End to end: requireTrustedRoot admits a chain anchored at a configured root.
func TestIssueRequireTrustedRootAcceptsTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "android-key-attestation",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	state.verifierRegistry = newVerifierRegistryWithRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation.Platform = "ANDROID"
	req.Attestation.Token = b64url.EncodeToString(chain)
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for trusted+strongbox attestation, got %d: %s", resp.StatusCode, respBytes)
	}
}

// buildSyntheticAkaChainAndRoot builds a self-contained leaf+root chain carrying
// no RootOfTrust. Returns the length-prefixed DER chain, the root cert, and the
// leaf cert.
func buildSyntheticAkaChainAndRoot(t *testing.T, securityLevel int) ([]byte, *x509.Certificate, *x509.Certificate) {
	return buildSyntheticAkaChainAndRootWithBoot(t, securityLevel, nil)
}

// buildSyntheticAkaChainAndRootWithBoot builds a self-signed root and a leaf
// signed by it, where the leaf carries the Android Key Attestation extension at
// the given security level and (optionally) the supplied RootOfTrust. Returns the
// length-prefixed DER chain, the root cert, and the leaf cert.
func buildSyntheticAkaChainAndRootWithBoot(
	t *testing.T,
	securityLevel int,
	rot *rootOfTrust,
) ([]byte, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic AKA Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDer)

	akaExtBytes := buildAttestationExtension(t, securityLevel, rot)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Synthetic AKA Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: androidKeyAttestationOID, Value: akaExtBytes},
		},
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDer)

	return concatLengthPrefixed(leafDer, rootDer), rootCert, leafCert
}

// buildChainWithoutAkaExtension builds an otherwise-valid leaf+root chain whose
// leaf omits the attestation extension. Returns the chain and the root cert.
func buildChainWithoutAkaExtension(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	rootPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic Root (no AKA)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDer, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	rootCert, _ := x509.ParseCertificate(rootDer)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf without AKA extension"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDer, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafPriv.PublicKey, rootPriv)
	return concatLengthPrefixed(leafDer, rootDer), rootCert
}

// buildAttestationExtension DER-encodes a KeyDescription for the attestation
// extension at the given security level. When rot is non-nil it is wrapped in its
// context-specific tag and placed in the TEE-enforced authorization list.
func buildAttestationExtension(t *testing.T, securityLevel int, rot *rootOfTrust) []byte {
	t.Helper()

	emptySeq := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
	}

	teeEnforced := emptySeq
	if rot != nil {

		rotDER, err := asn1.Marshal(*rot)
		if err != nil {
			t.Fatalf("marshal RootOfTrust: %v", err)
		}

		// Wrap the RootOfTrust SEQUENCE in its context-specific tag.
		wrapped := asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        authorizationListRootOfTrustTag,
			IsCompound: true,
			Bytes:      rotDER,
		}
		wrappedDER, err := asn1.Marshal(wrapped)
		if err != nil {
			t.Fatalf("marshal wrapped RootOfTrust: %v", err)
		}

		// The TEE-enforced authorization list is a SEQUENCE of tagged entries.
		teeEnforced = asn1.RawValue{
			Tag:        asn1.TagSequence,
			Class:      asn1.ClassUniversal,
			IsCompound: true,
			Bytes:      wrappedDER,
		}
	}

	type fullDesc struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TeeEnforced              asn1.RawValue
	}
	d := fullDesc{
		AttestationVersion:       4,
		AttestationSecurityLevel: asn1.Enumerated(securityLevel),
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   asn1.Enumerated(securityLevel),
		AttestationChallenge:     []byte("test-challenge"),
		UniqueID:                 []byte{},
		SoftwareEnforced:         emptySeq,
		TeeEnforced:              teeEnforced,
	}
	out, err := asn1.Marshal(d)
	if err != nil {
		t.Fatalf("marshal KeyDescription: %v", err)
	}
	return out
}

// verifiedBootRoT is a RootOfTrust for a locked device in the verified boot state.
func verifiedBootRoT() *rootOfTrust {
	return &rootOfTrust{
		VerifiedBootKey:   []byte{0xAA, 0xBB, 0xCC, 0xDD},
		DeviceLocked:      true,
		VerifiedBootState: asn1.Enumerated(verifiedBootStateVerified),
	}
}

// unverifiedBootRoT is a RootOfTrust for an unlocked device in the unverified boot state.
func unverifiedBootRoT() *rootOfTrust {
	return &rootOfTrust{
		VerifiedBootKey:   []byte{},
		DeviceLocked:      false,
		VerifiedBootState: asn1.Enumerated(verifiedBootStateUnverified),
	}
}

// concatLengthPrefixed joins DER certs into the wire chain format: each cert
// preceded by its big-endian uint16 length.
func concatLengthPrefixed(certs ...[]byte) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(c)))
		buf.Write(lengthPrefix)
		buf.Write(c)
	}
	return buf.Bytes()
}

// poolWith returns a cert pool containing the given certs.
func poolWith(t *testing.T, certs ...*x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range certs {
		if c == nil {
			t.Fatalf("poolWith: nil cert")
		}
		pool.AddCert(c)
	}
	return pool
}

// newTrustingVerifier returns a verifier whose only trusted root is the one from a
// freshly built synthetic chain at the given security level.
func newTrustingVerifier(t *testing.T, securityLevel int) *androidKeyAttestationVerifier {
	t.Helper()
	_, root, _ := buildSyntheticAkaChainAndRoot(t, securityLevel)
	return newAndroidKeyAttestationVerifier(poolWith(t, root))
}
