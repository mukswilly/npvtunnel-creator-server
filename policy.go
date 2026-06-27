package main

import (
	"fmt"
	"time"
)

// attestationDecision is the outcome of applying a policy to a request: whether
// to reject it, how long the issued config may live, and what to record.
type attestationDecision struct {
	// reject reports whether the request must be denied.
	reject bool

	// rejectReason explains a rejection.
	rejectReason string

	// ttl is the lifetime granted to the issued config.
	ttl time.Duration

	// logAttestation requests that the attestation outcome be recorded.
	logAttestation bool

	// verdict is the verifier result, when a verifier ran; nil otherwise.
	verdict *Verdict
}

// defaultConfigTtl is the config lifetime granted when none is configured.
const defaultConfigTtl = 1 * time.Hour

// configTtlMin and configTtlMax bound the permitted config lifetime.
const (
	configTtlMin = 60 * time.Second
	configTtlMax = 7 * 24 * time.Hour
)

// resolveConfigTtl returns the config lifetime for an entry, falling back to
// defaultConfigTtl when the entry is missing or specifies no positive TTL.
func resolveConfigTtl(entry *ConfigEntry) time.Duration {
	if entry == nil || entry.ConfigTtlSec <= 0 {
		return defaultConfigTtl
	}
	return time.Duration(entry.ConfigTtlSec) * time.Second
}

// evaluateAttestationPolicy applies a policy to a request's attestation and
// returns the resulting decision. baseTtl is the lifetime granted when the
// request is allowed at full trust. With no policy or the policy off, the
// request is allowed at baseTtl without inspecting the attestation.
func evaluateAttestationPolicy(
	policy *AttestationPolicy,
	attestation AttestationBlob,
	verifier AttestationVerifier,
	baseTtl time.Duration,
) attestationDecision {
	// No policy, or policy off: allow at full TTL, attestation ignored.
	if policy == nil || policy.Mode == AttestationModeOff {
		return attestationDecision{ttl: baseTtl}
	}

	// Run the verifier when one is configured and a token is present. A verifier
	// error is folded into an unverified verdict rather than failing evaluation.
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

			v = Verdict{Verified: false, Reason: "verifier error: " + err.Error()}
		}
		verdict = &v
	}

	// Decide whether the request counts as attested. With a verdict, start from
	// Verified and clear it if any enabled requirement is unmet. Without a
	// verifier, fall back to whether the blob merely claims an attestation.
	attested := false
	if verdict != nil {
		attested = verdict.Verified
		if policy.RequireHardwareBacked && !verdict.HardwareBacked {

			attested = false
		}
		if policy.RequireTrustedRoot && !verdict.TrustedRoot {

			attested = false
		}
		if policy.RequireVerifiedBoot && !(verdict.VerifiedBootState == "verified" && verdict.DeviceLocked) {

			attested = false
		}
	} else {
		attested = claimsAttestation(attestation)
	}

	switch policy.Mode {
	// Observe: never reject and never shorten the TTL; just record the outcome.
	case AttestationModeObserve:
		return attestationDecision{
			ttl:            baseTtl,
			logAttestation: true,
			verdict:        verdict,
		}

	// Soft: allow either way, but grant only the soft-failure TTL (capped at
	// baseTtl) when the request is not attested.
	case AttestationModeSoft:
		if attested {
			return attestationDecision{ttl: baseTtl, verdict: verdict}
		}

		ttl := softFailureTtl(policy)
		if ttl > baseTtl {
			ttl = baseTtl
		}
		return attestationDecision{ttl: ttl, verdict: verdict}

	// Strict: allow at full TTL when attested, otherwise reject with a reason
	// describing the specific requirement that was not met.
	case AttestationModeStrict:
		if attested {
			return attestationDecision{ttl: baseTtl, verdict: verdict}
		}
		reason := "no attestation claimed"
		if verdict != nil {
			reason = "verifier rejected: " + verdict.Reason

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
			ttl:          baseTtl,
			verdict:      verdict,
		}
	}

	// Unrecognized mode: allow at full TTL.
	return attestationDecision{ttl: baseTtl}
}

// claimsAttestation reports whether a blob purports to carry an attestation,
// without verifying it: it must name a platform other than NONE and carry a
// token. Used as the fallback when no verifier runs.
func claimsAttestation(a AttestationBlob) bool {
	if a.Platform == "" || a.Platform == "NONE" {
		return false
	}
	if a.Token == "" {
		return false
	}
	return true
}

// softFailureTtl returns the TTL granted to an unattested request under soft
// mode, falling back to defaultSoftFailureTtlSec when none is configured.
func softFailureTtl(policy *AttestationPolicy) time.Duration {
	sec := policy.SoftFailureTtlSec
	if sec <= 0 {
		sec = defaultSoftFailureTtlSec
	}
	return time.Duration(sec) * time.Second
}

// resolveIssuanceLimit returns the per-hour issuance cap a policy imposes. It
// returns 0 (no limit) when there is no policy or the policy is off, the
// configured cap when positive, and otherwise defaultMaxIssuancesPerHour.
func resolveIssuanceLimit(policy *AttestationPolicy) int {
	if policy == nil || policy.Mode == AttestationModeOff {
		return 0
	}
	if policy.MaxIssuancesPerHour > 0 {
		return policy.MaxIssuancesPerHour
	}
	return defaultMaxIssuancesPerHour
}

// strictDeviceAttestationPolicy returns a strict policy that requires a
// hardware-backed key, a trusted root, and verified boot via the
// android-key-attestation verifier.
func strictDeviceAttestationPolicy() *AttestationPolicy {
	return &AttestationPolicy{
		Mode:                  AttestationModeStrict,
		Verifier:              "android-key-attestation",
		RequireHardwareBacked: true,
		RequireTrustedRoot:    true,
		RequireVerifiedBoot:   true,
	}
}
