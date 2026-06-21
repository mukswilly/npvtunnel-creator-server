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

// ──────────────────────────────────────────────────────────────────
// Verifier-level tests
//
// These all build a synthetic [leaf, root] chain and inject the root
// into a private test pool. Tests that need to assert "untrusted root
// is rejected" use the production verifier (with Google roots) — its
// pool won't contain the synthetic root, so the chain rightfully
// fails to anchor.
// ──────────────────────────────────────────────────────────────────

// TestAkaVerifierRejectsNonAndroid — the AKA verifier only handles
// Platform = ANDROID. iOS is handled by the App Attest verifier;
// everything else falls through with a clear "not for me" verdict.
func TestAkaVerifierRejectsNonAndroid(t *testing.T) {
	v := newTrustingVerifier(t, akaSecurityLevelStrongBox) // pool contents irrelevant for this case
	verdict, err := v.Verify(AttestationBlob{Platform: "IOS", Token: "tok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("non-Android platform must not be verified by AKA")
	}
}

// TestAkaVerifierRejectsEmptyToken — minimal hygiene before we try
// to base64-decode anything.
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

// TestAkaVerifierRejectsMalformedBase64 — well-formed string of garbage.
// Should produce an error, not a panic, not a "verified" verdict.
func TestAkaVerifierRejectsMalformedBase64(t *testing.T) {
	v := newTrustingVerifier(t, akaSecurityLevelStrongBox)
	_, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: "!!!"})
	if err == nil {
		t.Fatalf("expected error on malformed base64")
	}
}

// TestAkaVerifierWithNoRootsFailsClosed — a verifier configured with
// no roots pool must not produce Verified=true verdicts, even for a
// structurally-valid chain. Fail closed: silent loss of trust anchor
// is worse than a noisy reject.
func TestAkaVerifierWithNoRootsFailsClosed(t *testing.T) {
	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(nil /* no roots */)
	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified || verdict.TrustedRoot {
		t.Fatalf("verifier with nil roots must fail closed, got %+v", verdict)
	}
}

// TestAkaVerifierAcceptsTrustedSynthChain — happy path. Inject the
// synthetic root into the test pool; the chain anchors; Verified +
// TrustedRoot both true.
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

// TestAkaVerifierRejectsUntrustedRoot — the cryptographic load-bearer
// A synthetic chain whose root is NOT in the
// verifier's pool must produce Verified=false even though the chain
// parses and signs cleanly.
func TestAkaVerifierRejectsUntrustedRoot(t *testing.T) {
	chain, _, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)

	// Build a pool containing some OTHER trusted cert (not our synth
	// root). Using a freshly-generated unrelated root is the realistic
	// representation of "production roots that don't contain this
	// chain's root."
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
	// Structural fields are still populated — that's intentional so
	// observe-mode logs see the security level even on untrusted
	// chains. The policy enforces the gate, not the verifier.
	if verdict.SecurityLevel != "strongbox" {
		t.Errorf("SecurityLevel should still be extracted, got %q", verdict.SecurityLevel)
	}
}

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

// TestAkaVerifierRejectsLeafWithoutExtension — a structurally-valid
// cert chain that's missing the AKA extension is not Android Key
// Attestation. Verifier should report verified=false with a clear
// reason rather than throwing.
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

// TestAkaVerifierExtractsVerifiedBootStateAndDeviceLocked — happy path
// for the verified-boot parser: a chain with verified+locked RootOfTrust
// surfaces both signals in the Verdict.
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

// TestAkaVerifierExtractsUnverifiedBootState — rooted-device signal:
// the verifier extracts the state without rejecting the chain itself
// (the policy layer decides what to do with the signal).
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

// TestAkaVerifierAttestationWithoutRootOfTrust — older Keymaster
// versions don't emit a RootOfTrust at all. Verifier must surface
// empty VerifiedBootState (not panic, not synthesize a value), so
// the policy layer can distinguish "absent" from "present and
// verified".
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

// TestIssueRequireVerifiedBootAcceptsVerifiedDevice — strict policy +
// requireVerifiedBoot accepts a chain that anchors at the test root
// AND carries verified+locked in its RoT.
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

// TestIssueRequireVerifiedBootRejectsUnverifiedDevice — same policy,
// rooted-device chain. The chain anchors fine; the policy rejects on
// the verified-boot gate alone.
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

// TestIssueRequireVerifiedBootRejectsAttestationWithoutRootOfTrust —
// the "fail closed when the signal is missing" case. An older
// Keymaster chain without RoT must be rejected when requireVerifiedBoot
// is set, not silently accepted.
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

// TestAkaProductionRootsLoad — sanity check on the embedded PEM bundle:
// the production verifier must construct without error and have at
// least one cert in its pool. If this fails, the bundle was corrupted.
func TestAkaProductionRootsLoad(t *testing.T) {
	pool, err := loadGoogleAkaRoots()
	if err != nil {
		t.Fatalf("loadGoogleAkaRoots: %v", err)
	}
	if pool == nil {
		t.Fatalf("nil pool from embedded bundle")
	}
	// Cross-check: a synth chain (not anchored at Google) must fail
	// when verified against the production pool.
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

// ──────────────────────────────────────────────────────────────────
// Registry tests
// ──────────────────────────────────────────────────────────────────

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

func TestVerifierRegistryRejectsUnknown(t *testing.T) {
	r := newVerifierRegistry()
	_, err := r.Lookup("from-the-future")
	if err == nil {
		t.Fatalf("unknown verifier name must be rejected")
	}
}

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

// TestConfigsFileRejectsUnknownVerifier — operator footgun guard:
// typing "android-key-attest" or otherwise misspelling the verifier
// name should fail at startup, not silently no-op.
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

// ──────────────────────────────────────────────────────────────────
// End-to-end integration tests via the HTTP server.
//
// The State is constructed normally, then its verifier registry is
// swapped for one anchored at the synthetic test root so the chain
// can validate without needing a real Google-signed token.
// ──────────────────────────────────────────────────────────────────

// TestIssueStrictWithVerifierRejectsSoftwareKey — software-only
// attestation token rejected when policy requires hardware backing.
// Proves the verifier verdict flows into the rejection decision.
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

// TestIssueRequireTrustedRootRejectsUntrustedRoot — an integration
// check. With requireTrustedRoot set, a chain
// whose root is NOT in the verifier's pool is rejected even when
// the leaf claims StrongBox.
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

	// State's verifier registry stays anchored at production Google
	// roots. The attacker's synthetic chain has a self-signed root —
	// not in the pool — so requireTrustedRoot rejects it.
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

// TestIssueRequireTrustedRootAcceptsTrustedRoot — symmetric positive
// test: same policy, but the verifier's pool contains the synth root,
// so the same chain now anchors and the config issues.
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

// ──────────────────────────────────────────────────────────────────
// Synthetic chain construction (test fixtures)
//
// Build a 2-cert chain (leaf + self-signed root) with the leaf carrying
// a valid Android Key Attestation extension. We don't try to mimic
// Google's real chain layout — just enough ASN.1 to exercise the
// verifier's parsing paths. The root cert is returned alongside the
// chain so tests can inject it into a CertPool when they want the
// chain to anchor.
// ──────────────────────────────────────────────────────────────────

// buildSyntheticAkaChainAndRoot returns a chain whose leaf has the
// requested security level but NO RootOfTrust in teeEnforced (the
// no-verified-boot happy path). For tests that need a RootOfTrust, use
// buildSyntheticAkaChainAndRootWithBoot.
//
//	chainBytes — length-prefixed DER [leaf, root]
//	rootCert   — the *x509.Certificate for the root, ready to add to a pool
//	leafCert   — convenience handle for tests that want to inspect it
func buildSyntheticAkaChainAndRoot(t *testing.T, securityLevel int) ([]byte, *x509.Certificate, *x509.Certificate) {
	return buildSyntheticAkaChainAndRootWithBoot(t, securityLevel, nil)
}

// buildSyntheticAkaChainAndRootWithBoot is the full-control builder.
// Pass a non-nil *rootOfTrust to include a RootOfTrust in teeEnforced
// with the given verified-boot state + deviceLocked. Pass nil to
// produce a chain without RootOfTrust (the legacy case).
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

// buildChainWithoutAkaExtension returns a synthetic chain whose leaf
// is missing the AKA extension, plus the root for pool injection.
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

// buildAttestationExtension constructs a full 8-field KeyDescription
// SEQUENCE matching what parseKeyDescription expects. Pass a non-nil
// rot to embed a RootOfTrust at tag [704] inside teeEnforced; pass
// nil for an attestation that doesn't carry the verified-boot signal.
func buildAttestationExtension(t *testing.T, securityLevel int, rot *rootOfTrust) []byte {
	t.Helper()

	emptySeq := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
	}

	teeEnforced := emptySeq
	if rot != nil {
		// Marshal the RootOfTrust SEQUENCE first.
		rotDER, err := asn1.Marshal(*rot)
		if err != nil {
			t.Fatalf("marshal RootOfTrust: %v", err)
		}
		// Wrap it in a [704] EXPLICIT context-tagged element. The
		// wrapping is constructed (it contains another tag header
		// underneath), so IsCompound=true.
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
		// Build the AuthorizationList SEQUENCE containing just the
		// wrapped element. Production AuthorizationLists have many
		// more fields; the verifier skips past them looking for tag
		// 704, so a one-field list exercises the same code path.
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

// verifiedBootRoT is a tiny convenience for the common "OEM-signed,
// bootloader locked" RootOfTrust used by happy-path tests.
func verifiedBootRoT() *rootOfTrust {
	return &rootOfTrust{
		VerifiedBootKey:   []byte{0xAA, 0xBB, 0xCC, 0xDD},
		DeviceLocked:      true,
		VerifiedBootState: asn1.Enumerated(verifiedBootStateVerified),
	}
}

// unverifiedBootRoT represents a rooted / bootloader-unlocked device:
// the chain itself is anchored at Google and the key is hardware-
// backed, but the running OS isn't OEM-signed.
func unverifiedBootRoT() *rootOfTrust {
	return &rootOfTrust{
		VerifiedBootKey:   []byte{},
		DeviceLocked:      false,
		VerifiedBootState: asn1.Enumerated(verifiedBootStateUnverified),
	}
}

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

// poolWith returns a CertPool seeded with the given certs.
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

// newTrustingVerifier returns a verifier whose pool contains the root
// of a freshly-built synth chain at the requested security level. Use
// for verifier-level tests where the test focuses on input-shape
// checks rather than trust anchoring.
func newTrustingVerifier(t *testing.T, securityLevel int) *androidKeyAttestationVerifier {
	t.Helper()
	_, root, _ := buildSyntheticAkaChainAndRoot(t, securityLevel)
	return newAndroidKeyAttestationVerifier(poolWith(t, root))
}
