package main

import (
	"fmt"
	"time"
)

// attestationDecision is the outcome of applying an AttestationPolicy to
// one IssueRequest. Returned by evaluateAttestationPolicy so the handler
// has a single switch instead of nested ifs.
type attestationDecision struct {
	// reject is true when /v1/issue should fail closed with 401
	// attestation_failed. Set when:
	//   - strict mode + no claimed attestation
	//   - any mode + verifier returned Verified=false (after being
	//     configured)
	//   - any mode + RequireHardwareBacked + verdict.HardwareBacked == false
	reject bool

	// rejectReason is a short, log-safe explanation of why reject is
	// true. Used for the audit log + error detail.
	rejectReason string

	// ttl is the credential lifetime to use for this issuance. Always
	// set, regardless of mode. The handler uses this in place of the
	// previously-hardcoded 1 hour.
	ttl time.Duration

	// logAttestation, when true, hints to the handler to emit a more
	// detailed audit-log record of the attestation evidence the client
	// claimed. Currently set by "observe" mode; ignored by the handler
	// for other modes (they get the standard log shape).
	logAttestation bool

	// verdict, if non-nil, was produced by an AttestationVerifier and
	// is logged alongside other audit fields. nil when no verifier is
	// configured for this policy.
	verdict *Verdict
}

// defaultCredTtl is the credential lifetime when no policy is configured
// or the policy is "off"/"observe"/"strict" (the soft mode is the only
// one that shortens it).
const defaultCredTtl = 1 * time.Hour

// evaluateAttestationPolicy applies the (possibly-nil) policy to the
// incoming request and returns what the handler should do.
//
// Reading the truth table:
//
//   policy == nil OR policy.mode == "off"
//     -> proceed, full TTL
//   policy.mode == "observe"
//     -> proceed, full TTL, log attestation evidence
//   policy.mode == "soft"
//     -> proceed
//        if client claimed attestation: full TTL
//        if client didn't:               short TTL
//   policy.mode == "strict"
//     -> if client claimed attestation: proceed, full TTL
//        if client didn't:               reject
//
// "claimed attestation" — when no Verifier is configured — means
// Attestation.Platform != "NONE" and Attestation.Token is non-empty.
// That's honest signal against indifferent malicious clients but not
// against motivated ones; verifier-backed checking
// supersedes it whenever the policy names a Verifier.
func evaluateAttestationPolicy(
	policy *AttestationPolicy,
	attestation AttestationBlob,
	verifier AttestationVerifier,
) attestationDecision {
	if policy == nil || policy.Mode == AttestationModeOff {
		return attestationDecision{ttl: defaultCredTtl}
	}

	// Run the verifier if one is configured for this policy. The
	// verdict supersedes the "claimed attestation" signal; without a
	// verifier we fall back to the 3.4b claimed-only check.
	//
	// Apple App Attest's verification needs the per-config appId,
	// which the generic AttestationVerifier interface doesn't carry.
	// We route through the type-specific entry point when we
	// recognize the App Attest verifier.
	var verdict *Verdict
	if verifier != nil && attestation.Token != "" {
		var v Verdict
		var err error
		if aa, ok := verifier.(*appleAppAttestVerifier); ok {
			v, err = aa.verifyWithAppID(attestation, policy.AppID)
		} else {
			v, err = verifier.Verify(attestation)
		}
		if err != nil {
			// Verifier couldn't produce a verdict at all (malformed
			// input). Treat as "not verified" — caller's policy
			// decides whether that's a reject.
			v = Verdict{Verified: false, Reason: "verifier error: " + err.Error()}
		}
		verdict = &v
	}

	// "attested" means: if a verifier is configured, it produced
	// Verified=true AND any additional policy requirements
	// (RequireHardwareBacked, RequireTrustedRoot) are satisfied;
	// otherwise, the client just claimed attestation (3.4b behavior).
	attested := false
	if verdict != nil {
		attested = verdict.Verified
		if policy.RequireHardwareBacked && !verdict.HardwareBacked {
			// Hardware requirement isn't met. Treat as unattested
			// regardless of Verified — software-only keys don't
			// satisfy a policy that demands TEE/StrongBox.
			attested = false
		}
		if policy.RequireTrustedRoot && !verdict.TrustedRoot {
			// Chain-to-Google requirement isn't met. The leaf may
			// have parsed cleanly and claimed StrongBox, but it
			// didn't terminate at a known Google AKA root, so the
			// hardware claim isn't cryptographically backed.
			attested = false
		}
		if policy.RequireVerifiedBoot && !(verdict.VerifiedBootState == "verified" && verdict.DeviceLocked) {
			// Verified-boot requirement isn't met. The chain may
			// anchor at Google AND the key may be hardware-backed,
			// but the device's bootloader was unlocked OR the OS
			// image wasn't signed by the OEM key. Reject — the
			// rooted-recipient threat is exactly what this gate
			// is for.
			attested = false
		}
	} else {
		attested = claimsAttestation(attestation)
	}

	switch policy.Mode {
	case AttestationModeObserve:
		return attestationDecision{
			ttl:            defaultCredTtl,
			logAttestation: true,
			verdict:        verdict,
		}

	case AttestationModeSoft:
		if attested {
			return attestationDecision{ttl: defaultCredTtl, verdict: verdict}
		}
		// Short TTL for unattested requests under soft mode. Bounds the
		// blast radius if this device turns out to be compromised.
		return attestationDecision{ttl: softFailureTtl(policy), verdict: verdict}

	case AttestationModeStrict:
		if attested {
			return attestationDecision{ttl: defaultCredTtl, verdict: verdict}
		}
		reason := "no attestation claimed"
		if verdict != nil {
			reason = "verifier rejected: " + verdict.Reason
			// Layered checks ordered most-specific last so the final
			// reason names the exact gate that failed.
			if policy.RequireHardwareBacked && !verdict.HardwareBacked {
				reason = "requireHardwareBacked: got " + verdict.SecurityLevel
			}
			if policy.RequireTrustedRoot && !verdict.TrustedRoot {
				reason = "requireTrustedRoot: chain not anchored at a Google AKA root"
			}
			if policy.RequireVerifiedBoot && !(verdict.VerifiedBootState == "verified" && verdict.DeviceLocked) {
				reason = fmt.Sprintf(
					"requireVerifiedBoot: got state=%q deviceLocked=%v",
					verdict.VerifiedBootState, verdict.DeviceLocked,
				)
			}
		}
		return attestationDecision{
			reject:       true,
			rejectReason: reason,
			ttl:          defaultCredTtl,
			verdict:      verdict,
		}
	}

	// Unrecognized mode shouldn't happen — validAttestationMode runs at
	// configs.json load. Defense in depth: treat as "off".
	return attestationDecision{ttl: defaultCredTtl}
}

// claimsAttestation returns true when the client sent something in the
// attestation field that's worth at least logging. The bar is low:
// platform != NONE and a non-empty token. This is the 3.4b fallback
// used when no Verifier is configured — once a Verifier runs, its
// Verdict supersedes this signal.
func claimsAttestation(a AttestationBlob) bool {
	if a.Platform == "" || a.Platform == "NONE" {
		return false
	}
	if a.Token == "" {
		return false
	}
	return true
}

// softFailureTtl returns the TTL to use under soft mode when the client
// didn't claim attestation. Falls back to defaultSoftFailureTtlSec if the
// policy doesn't override it.
func softFailureTtl(policy *AttestationPolicy) time.Duration {
	sec := policy.SoftFailureTtlSec
	if sec <= 0 {
		sec = defaultSoftFailureTtlSec
	}
	return time.Duration(sec) * time.Second
}

// resolveIssuanceLimit picks the per-(device, config) issuance rate
// limit from the policy. Truth table:
//
//   policy == nil OR mode == "off"
//     -> 0 (no limit). Preserves 3.1a back-compat for deployments
//     that haven't configured any policy.
//   policy.MaxIssuancesPerHour > 0
//     -> use the configured value.
//   policy.MaxIssuancesPerHour <= 0 AND mode != "off"
//     -> defaultMaxIssuancesPerHour (10). Sensible cap whenever the
//     creator's said anything about attestation.
//
// Returned value is the requests/hour cap; a window of exactly 1 hour
// is hardcoded in the handler (no per-policy window override yet —
// keeps the policy surface small).
func resolveIssuanceLimit(policy *AttestationPolicy) int {
	if policy == nil || policy.Mode == AttestationModeOff {
		return 0
	}
	if policy.MaxIssuancesPerHour > 0 {
		return policy.MaxIssuancesPerHour
	}
	return defaultMaxIssuancesPerHour
}
