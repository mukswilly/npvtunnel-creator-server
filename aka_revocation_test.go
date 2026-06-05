package main

import (
	"math/big"
	"strings"
	"testing"
)

// ─── parseRevocationStatus ────────────────────────────────────────

func TestParseRevocationStatusExtractsEntries(t *testing.T) {
	body := []byte(`{
		"entries": {
			"aabbcc": {"status": "REVOKED", "reason": "compromised"},
			"112233": {"status": "SUSPENDED"},
			"ffff":   {"status": "REVOKED", "comment": "soft brick"}
		}
	}`)
	out, err := parseRevocationStatus(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out["aabbcc"] != "REVOKED" {
		t.Errorf("expected REVOKED for aabbcc, got %q", out["aabbcc"])
	}
	if out["112233"] != "SUSPENDED" {
		t.Errorf("expected SUSPENDED for 112233, got %q", out["112233"])
	}
	if out["ffff"] != "REVOKED" {
		t.Errorf("expected REVOKED for ffff, got %q", out["ffff"])
	}
}

func TestParseRevocationStatusNormalizesCase(t *testing.T) {
	// Real Google responses use lowercase hex; defensive lowercasing
	// in the parser means a mid-case payload still keys consistently.
	body := []byte(`{"entries": {"AABBCC": {"status": "REVOKED"}}}`)
	out, _ := parseRevocationStatus(body)
	if _, present := out["aabbcc"]; !present {
		t.Errorf("expected lowercase-normalized key, got map %v", out)
	}
}

func TestParseRevocationStatusEmpty(t *testing.T) {
	out, err := parseRevocationStatus([]byte(`{"entries": {}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty map, got %v", out)
	}
}

func TestParseRevocationStatusInvalidJSON(t *testing.T) {
	_, err := parseRevocationStatus([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// ─── staticRevocationOracle ───────────────────────────────────────

func TestStaticOracleHitsAndMisses(t *testing.T) {
	o := newStaticRevocationOracle("aabbcc", "deadbeef")

	hit, ok := o.IsRevoked(big.NewInt(0xAABBCC))
	if !ok || !hit {
		t.Errorf("expected hit for AABBCC, got hit=%v ok=%v", hit, ok)
	}
	hitDB, _ := o.IsRevoked(new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	if !hitDB {
		t.Error("expected hit for DEADBEEF")
	}

	hit, ok = o.IsRevoked(big.NewInt(0x424242))
	if !ok {
		t.Error("dataAvailable should be true for static oracle on miss too")
	}
	if hit {
		t.Error("expected miss for 424242")
	}
}

func TestNoopOracleAlwaysSaysNoData(t *testing.T) {
	o := noopRevocationOracle{}
	hit, ok := o.IsRevoked(big.NewInt(1))
	if ok || hit {
		t.Errorf("noop oracle should report dataAvailable=false, got hit=%v ok=%v", hit, ok)
	}
}

// ─── Verifier-level integration ───────────────────────────────────
//
// Build a synthetic AKA chain, then check the verifier rejects it
// when the chain's leaf serial is on the revocation list.

func TestAkaVerifierRejectsRevokedLeafSerial(t *testing.T) {
	chain, root, leaf := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root)).
		withRevocationOracle(newStaticRevocationOracle(leaf.SerialNumber.Text(16)))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("revoked leaf must NOT verify, got %+v", verdict)
	}
	if verdict.TrustedRoot {
		t.Error("TrustedRoot must be demoted to false on revocation hit")
	}
	if !strings.Contains(verdict.Reason, "revocation") {
		t.Errorf("reason should mention revocation, got %q", verdict.Reason)
	}
}

func TestAkaVerifierRejectsRevokedRootSerial(t *testing.T) {
	// Google flags intermediates too; a compromised batch-signing
	// intermediate should invalidate every leaf under it. Use the
	// root's serial here — in our 2-cert synth chain, the "root"
	// stands in for an intermediate Google might flag.
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root)).
		withRevocationOracle(newStaticRevocationOracle(root.SerialNumber.Text(16)))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified {
		t.Fatalf("chain with revoked intermediate must NOT verify, got %+v", verdict)
	}
}

func TestAkaVerifierUnrevokedChainStillVerifies(t *testing.T) {
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root)).
		withRevocationOracle(newStaticRevocationOracle("doesnotmatch"))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("chain with no revoked serial should still verify, got %+v", verdict)
	}
}

func TestAkaVerifierSkipsRevocationGateWhenNoData(t *testing.T) {
	// noopRevocationOracle reports dataAvailable=false for every
	// query. The verifier should treat that as "no gate" rather
	// than failing — this is the offline / pre-warm-failed path
	// that we deliberately want to fail-open, since Google's
	// revocation feed is best-effort and the audience can't afford
	// lockout when Google is unreachable.
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root)).
		withRevocationOracle(noopRevocationOracle{})

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("verifier should fall back to no-revocation-gate when oracle has no data, got %+v", verdict)
	}
}

func TestAkaVerifierWithoutOracleStillWorks(t *testing.T) {
	// Back-compat for tests/callers that construct the verifier
	// without ever calling withRevocationOracle.
	chain, root, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, root))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.Verified {
		t.Fatalf("nil oracle should be back-compat with pre-3.4e-iv behavior, got %+v", verdict)
	}
}

// ─── Untrusted chain + revocation: revocation gate is gated on trust ──

func TestAkaVerifierDoesNotConsultRevocationForUntrustedChain(t *testing.T) {
	// A chain whose root we don't trust shouldn't be cross-checked
	// against Google's revocation feed — Google's signals about
	// other roots' serials are meaningless for an untrusted chain.
	// The verdict's primary failure is "untrusted root," not
	// "revoked."
	chain, _, leaf := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	_, otherRoot, _ := buildSyntheticAkaChainAndRoot(t, akaSecurityLevelStrongBox)
	v := newAndroidKeyAttestationVerifier(poolWith(t, otherRoot)).
		withRevocationOracle(newStaticRevocationOracle(leaf.SerialNumber.Text(16)))

	verdict, err := v.Verify(AttestationBlob{Platform: "ANDROID", Token: b64url.EncodeToString(chain)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Verified || verdict.TrustedRoot {
		t.Fatalf("untrusted chain must not verify, got %+v", verdict)
	}
	// The reason should be about the untrusted root, not the
	// revocation — the gate ordering matters for the audit log.
	if strings.Contains(verdict.Reason, "revocation") {
		t.Errorf("verdict should fail on trust before revocation, got %q", verdict.Reason)
	}
}
