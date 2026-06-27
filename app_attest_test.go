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

// The App Attest verifier returns an unverified verdict for a non-IOS platform.
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

// An empty expected appID fails verification with a reason naming appId.
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

// An empty token yields an unverified verdict.
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

// With no trust roots configured the verifier fails closed even on a valid object.
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

// A trusted-root prod-AAGUID object verifies; App Attest is always hardware-backed
// (reported as "strongbox") and carries no boot state.
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
		t.Error("HardwareBacked must be true for App Attest (always hardware-backed)")
	}
	if verdict.SecurityLevel != "strongbox" {
		t.Errorf("SecurityLevel = %q, want strongbox", verdict.SecurityLevel)
	}

	if verdict.VerifiedBootState != "" {
		t.Errorf("VerifiedBootState should be empty for App Attest, got %q", verdict.VerifiedBootState)
	}
	if !strings.Contains(verdict.Reason, "prod") {
		t.Errorf("reason should mention aaguid env, got %q", verdict.Reason)
	}
}

// An object carrying the development AAGUID verifies and the reason notes "dev".
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

// Verifying against a different appID fails the rpIdHash binding check.
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

// An object whose root is not in the pool does not verify.
func TestAppAttestRejectsUntrustedRoot(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, _ := buildSyntheticAppAttest(t, appID, aaguidProd)

	// Seed the pool from a second, unrelated object so the first cannot anchor.
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

// A nonce that no longer matches the challenge bound into the credCert fails.
func TestAppAttestRejectsNonceMismatch(t *testing.T) {
	appID := "TEAM1234.com.example.app"
	blob, _, root := buildSyntheticAppAttest(t, appID, aaguidProd)

	// Replace the nonce so it no longer derives the credCert's embedded value.
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

// The embedded Apple production root loads, and a synthetic object must not anchor at it.
func TestAppAttestProductionRootsLoad(t *testing.T) {
	pool, err := loadAppleAppAttestRoots()
	if err != nil {
		t.Fatalf("loadAppleAppAttestRoots: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}

	blob, _, _ := buildSyntheticAppAttest(t, "TEAM.app", aaguidProd)
	v := newAppleAppAttestVerifier(pool)
	verdict, _ := v.verifyWithAppID(blob, "TEAM.app")
	if verdict.Verified {
		t.Fatal("synth chain must not anchor at Apple's production root")
	}
}

// The registry resolves the apple-app-attest verifier name.
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

// An apple-app-attest policy without an appId fails to load.
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

// An apple-app-attest policy with an appId loads successfully.
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

// End to end: an object built for a different appID than the config expects is
// rejected with 401.
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

	blob, _, root := buildSyntheticAppAttest(t, "ATTACKER.com.different.app", aaguidProd)
	// Point the App Attest verifier at the synthetic root so the test object anchors.
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

// End to end: an object whose appID matches the config is admitted with 200.
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

// buildSyntheticAppAttest builds a complete synthetic Apple App Attest object for
// the given appID and AAGUID: a leaf+root chain whose leaf credCert carries the
// nonce extension, authenticator data binding the appID and credential, and the
// whole thing CBOR-encoded. Returns the attestation blob (with the matching
// challenge as the nonce), the leaf cert, and the root cert.
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

	challenge := []byte("synthetic-app-attest-challenge-32b!")

	// The credential ID is the SHA-256 of the leaf public key; rpIdHash binds the appID.
	leafPubUncompressed := marshalUncompressed(&leafPriv.PublicKey)
	credentialID := sha256.Sum256(leafPubUncompressed)
	rpIDHash := sha256.Sum256([]byte(appID))

	// Authenticator data: rpIdHash | flags | counter | AAGUID | credIdLen | credId.
	authData := make([]byte, 0, 55+len(credentialID))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x40)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)
	authData = append(authData, counter...)
	authData = append(authData, aaguid...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	authData = append(authData, credIDLen...)
	authData = append(authData, credentialID[:]...)

	// Expected nonce = SHA-256(authData || SHA-256(challenge)).
	clientDataHash := sha256.Sum256(challenge)
	composite := append([]byte{}, authData...)
	composite = append(composite, clientDataHash[:]...)
	nonce := sha256.Sum256(composite)

	// The credCert extension is a SEQUENCE holding the nonce OCTET STRING under
	// context tag [1].
	innerNonceDER, err := asn1.Marshal(nonce[:])
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

	// Assemble the CBOR App Attest object: format id, statement (cert chain +
	// receipt), and authenticator data.
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
