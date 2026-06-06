package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/fxamacker/cbor/v2"
)

// ──────────────────────────────────────────────────────────────────
// Verifier-level tests
// ──────────────────────────────────────────────────────────────────

func TestAppAttestRejectsNonIOS(t *testing.T) {
	v := newAppleAppAttestVerifier(x509.NewCertPool())
	verdict, err := v.verifyWithAppID(
		AttestationBlob{Platform: "ANDROID", Token: "tok"},
		"TEAM.app",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("non-iOS platform must not be verified by App Attest")
	}
}

func TestAppAttestRejectsEmptyAppID(t *testing.T) {
	v := newAppleAppAttestVerifier(x509.NewCertPool())
	verdict, err := v.verifyWithAppID(
		AttestationBlob{Platform: "IOS", Token: "tok", Nonce: ""},
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("empty appID must fail")
	}
	if !strings.Contains(verdict.Reason, "appId") {
		t.Errorf("reason should mention appId, got %q", verdict.Reason)
	}
}

func TestAppAttestRejectsEmptyToken(t *testing.T) {
	v := newAppleAppAttestVerifier(x509.NewCertPool())
	verdict, err := v.verifyWithAppID(
		AttestationBlob{Platform: "IOS", Token: ""},
		"TEAM.app",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("empty token must not verify")
	}
}

func TestAppAttestWithNoRootsFailsClosed(t *testing.T) {
	blob, _, _ := buildSyntheticAppAttest(t, "TEAM1234.com.example.app", aaguidProd)
	v := newAppleAppAttestVerifier(nil)
	verdict, err := v.verifyWithAppID(blob, "TEAM1234.com.example.app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified || verdict.TrustedRoot {
		t.Fatalf("verifier with nil roots must fail closed, got %+v", verdict)
	}
}

func TestAppAttestAcceptsTrustedSynthChain(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, root := buildSyntheticAppAttest(t, appID, aaguidProd)
	v := newAppleAppAttestVerifier(poolWith(t, root))

	verdict, err := v.verifyWithAppID(blob, appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("trusted-root synth chain should verify, got %+v", verdict)
	}
	if !verdict.TrustedRoot {
		t.Error("TrustedRoot must be true when chain anchors")
	}
	if !verdict.HardwareBacked {
		t.Error("HardwareBacked must be true for App Attest (always Secure Enclave)")
	}
	if verdict.SecurityLevel != "strongbox" {
		t.Errorf("SecurityLevel = %q, want strongbox", verdict.SecurityLevel)
	}
	// App Attest carries no verified-boot signal — empty by design.
	if verdict.VerifiedBootState != "" {
		t.Errorf("VerifiedBootState should be empty for App Attest, got %q", verdict.VerifiedBootState)
	}
	if !strings.Contains(verdict.Reason, "prod") {
		t.Errorf("reason should mention aaguid env, got %q", verdict.Reason)
	}
}

func TestAppAttestAcceptsDevAaguid(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, root := buildSyntheticAppAttest(t, appID, aaguidDev)
	v := newAppleAppAttestVerifier(poolWith(t, root))

	verdict, err := v.verifyWithAppID(blob, appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("dev-env App Attest should verify, got %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "dev") {
		t.Errorf("reason should mention 'dev' aaguid kind, got %q", verdict.Reason)
	}
}

func TestAppAttestRejectsWrongAppID(t *testing.T) {
	blob, _, root := buildSyntheticAppAttest(t, "TEAM1234.com.example.app", aaguidProd)
	v := newAppleAppAttestVerifier(poolWith(t, root))

	verdict, err := v.verifyWithAppID(blob, "OTHER999.com.different.app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("attestation with mismatched appID must not verify")
	}
	if !strings.Contains(verdict.Reason, "rpIdHash") {
		t.Errorf("reason should name rpIdHash check, got %q", verdict.Reason)
	}
}

func TestAppAttestRejectsUntrustedRoot(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, _ := buildSyntheticAppAttest(t, appID, aaguidProd)
	// Pool with an unrelated root.
	_, _, otherRoot := buildSyntheticAppAttest(t, appID, aaguidProd)
	v := newAppleAppAttestVerifier(poolWith(t, otherRoot))

	verdict, err := v.verifyWithAppID(blob, appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("untrusted root must NOT verify")
	}
	if verdict.TrustedRoot {
		t.Error("TrustedRoot must be false for unknown root")
	}
}

func TestAppAttestRejectsNonceMismatch(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, root := buildSyntheticAppAttest(t, appID, aaguidProd)
	// Tamper with the nonce field after build — verifier should detect.
	blob.Nonce = b64url.EncodeToString([]byte("different challenge"))
	v := newAppleAppAttestVerifier(poolWith(t, root))

	verdict, err := v.verifyWithAppID(blob, appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatal("attestation with mismatched challenge must not verify")
	}
	if !strings.Contains(verdict.Reason, "nonce") {
		t.Errorf("reason should name nonce mismatch, got %q", verdict.Reason)
	}
}

func TestAppAttestProductionRootsLoad(t *testing.T) {
	pool, err := loadAppleAppAttestRoots()
	if err != nil {
		t.Fatalf("loadAppleAppAttestRoots: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
	// Synth chain must not anchor at production roots.
	blob, _, _ := buildSyntheticAppAttest(t, "TEAM.app", aaguidProd)
	v := newAppleAppAttestVerifier(pool)
	verdict, _ := v.verifyWithAppID(blob, "TEAM.app")
	if verdict.Verified {
		t.Fatal("synth chain must not anchor at Apple's production root")
	}
}

// ──────────────────────────────────────────────────────────────────
// Registry + configs.json validation
// ──────────────────────────────────────────────────────────────────

func TestVerifierRegistryKnowsAppAttest(t *testing.T) {
	r := newVerifierRegistry()
	v, err := r.Lookup("apple-app-attest")
	if err != nil {
		t.Fatalf("apple-app-attest should be registered: %v", err)
	}
	if v == nil {
		t.Fatal("registry returned nil for apple-app-attest")
	}
}

func TestConfigsFileRejectsAppAttestWithoutAppID(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "apple-app-attest"
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err == nil {
		t.Fatal("expected error: apple-app-attest requires appId")
	}
	if !strings.Contains(err.Error(), "appId") {
		t.Errorf("error should mention appId, got %v", err)
	}
}

func TestConfigsFileAcceptsAppAttestWithAppID(t *testing.T) {
	dir := t.TempDir()
	raw := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "apple-app-attest",
			"appId": "TEAM1234.com.example.app"
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(raw), 0o600)
	_, err := NewStateWithDir(dir)
	if err != nil {
		t.Fatalf("appId-set config should load: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────
// End-to-end integration via the HTTP server
// ──────────────────────────────────────────────────────────────────

func TestIssueAppAttestStrictRejectsWrongAppID(t *testing.T) {
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "apple-app-attest",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true,
			"appId": "EXPECTED.com.example.app"
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	// Synthesize an attestation for a DIFFERENT app — the rpIdHash
	// check should reject it.
	blob, _, root := buildSyntheticAppAttest(t, "ATTACKER.com.different.app", aaguidProd)
	state.verifierRegistry = newVerifierRegistryWithAppAttestRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation = blob
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for app ID mismatch, got %d: %s", resp.StatusCode, out)
	}
}

func TestIssueAppAttestStrictAcceptsMatchingAppID(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	dir := t.TempDir()
	configs := `[{
		"configId": "AAAAAAAAAAAAAAAAAAAAAA",
		"config": {"name":"a","address":"vpn:443","type":"V2RAY","v2rayProfile":{"server":"vpn","serverPort":"443","password":"a1b2c3d4-0000-4000-8000-000000000001"}},
		"attestationPolicy": {
			"mode": "strict",
			"verifier": "apple-app-attest",
			"requireHardwareBacked": true,
			"requireTrustedRoot": true,
			"appId": "` + appID + `"
		}
	}]`
	os.WriteFile(filepath.Join(dir, "configs.json"), []byte(configs), 0o600)
	state, _ := NewStateWithDir(dir)

	blob, _, root := buildSyntheticAppAttest(t, appID, aaguidProd)
	state.verifierRegistry = newVerifierRegistryWithAppAttestRoots(poolWith(t, root))

	ts := newTestServerWithState(t, state)
	defer ts.Close()

	devPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := buildSignedIssueRequest(t, devPriv, "AAAAAAAAAAAAAAAAAAAAAA")
	req.Attestation = blob
	req.RequestSignature = signWithP256(t, devPriv, issueRequestSigningInput(&req))

	body, _ := json.Marshal(req)
	resp, _ := http.Post(ts.URL+"/v1/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for matching app ID, got %d: %s", resp.StatusCode, out)
	}
}

// ──────────────────────────────────────────────────────────────────
// Synthetic App Attest object construction
//
// Builds a 2-cert chain (leaf + self-signed root). The leaf carries
// the App Attest credCert extension with a properly-computed nonce.
// authData is hand-crafted to the App Attest layout with the right
// rpIdHash and credentialId.
//
// This exercises the verifier end-to-end without needing a real iOS
// device. Real-device coverage is on the roadmap as G2b.
// ──────────────────────────────────────────────────────────────────

// buildSyntheticAppAttest returns:
//
//	blob — AttestationBlob with platform=IOS, base64url-encoded CBOR
//	       token, and base64url-encoded challenge in Nonce.
//	leafCert — convenience handle
//	rootCert — for adding to a test trust pool
func buildSyntheticAppAttest(
	t *testing.T,
	appID string,
	aaguid []byte,
) (AttestationBlob, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic App Attest Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Pick a stable challenge for this synthetic scenario.
	challenge := []byte("synthetic-app-attest-challenge-32b!")

	// authData layout. We construct it BEFORE the leaf cert because
	// the leaf cert's credCert extension must contain a nonce
	// computed over the authData + clientDataHash, and the leaf's
	// pubkey must hash to the credentialId inside authData.
	leafPubUncompressed := marshalUncompressed(&leafPriv.PublicKey)
	credentialID := sha256.Sum256(leafPubUncompressed)
	rpIDHash := sha256.Sum256([]byte(appID))

	authData := make([]byte, 0, 55+len(credentialID))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x40) // flags: AT bit set
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0) // signCounter must be 0 for attestation
	authData = append(authData, counter...)
	authData = append(authData, aaguid...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	authData = append(authData, credIDLen...)
	authData = append(authData, credentialID[:]...)
	// COSE key omitted — verifier doesn't read it.

	// Compute the nonce the leaf's credCert extension must carry:
	// SHA256(authData || SHA256(challenge)).
	clientDataHash := sha256.Sum256(challenge)
	composite := append([]byte{}, authData...)
	composite = append(composite, clientDataHash[:]...)
	nonce := sha256.Sum256(composite)

	// Build the credCert extension value: OCTET STRING containing
	// SEQUENCE { [1] EXPLICIT OCTET STRING nonce }.
	innerNonceDER, err := asn1.Marshal(nonce[:]) // produces OCTET STRING 04 20 ...
	if err != nil {
		t.Fatalf("marshal inner nonce: %v", err)
	}
	tagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      innerNonceDER,
	}
	taggedDER, err := asn1.Marshal(tagged)
	if err != nil {
		t.Fatalf("marshal context-tagged nonce: %v", err)
	}
	credSeq := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      taggedDER,
	}
	credSeqDER, err := asn1.Marshal(credSeq)
	if err != nil {
		t.Fatalf("marshal credCert SEQUENCE: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Synthetic App Attest Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: appleAppAttestOID, Value: credSeqDER},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Build the CBOR attestation object.
	att := appAttestObject{
		Fmt: "apple-appattest",
		AttStmt: appAttestStmt{
			X5c:     [][]byte{leafDER, rootDER},
			Receipt: []byte{},
		},
		AuthData: authData,
	}
	tokenBytes, err := cbor.Marshal(att)
	if err != nil {
		t.Fatalf("marshal CBOR: %v", err)
	}

	return AttestationBlob{
		Platform: "IOS",
		Token:    b64url.EncodeToString(tokenBytes),
		Nonce:    b64url.EncodeToString(challenge),
	}, leafCert, rootCert
}
