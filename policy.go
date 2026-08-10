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
//
// The verifier is resolved here rather than by the caller because which one
// runs depends on the requester's platform: a policy can carry one arm per
// platform (see [AttestationPolicy.armFor]). lookup resolves a verifier name to
// an implementation; a resolution failure is a server misconfiguration and is
// returned as an error rather than folded into a verdict.
func evaluateAttestationPolicy(
	policy *AttestationPolicy,
	attestation AttestationBlob,
	lookup func(name string) (AttestationVerifier, error),
	baseTtl time.Duration,
) (attestationDecision, error) {
	// No policy, or policy off: allow at full TTL, attestation ignored.
	if policy == nil || policy.Mode == AttestationModeOff {
		return attestationDecision{ttl: baseTtl}, nil
	}

	// Select the arm for the requester's platform. A policy that defines arms
	// but none for this platform leaves the request unattestable — there is no
	// rule it could satisfy — so evaluation proceeds with a nil arm and no
	// verdict, which the modes below handle as "not attested".
	arm, hasArm := policy.armFor(attestation.Platform)

	var verifier AttestationVerifier
	if hasArm && arm.Verifier != "" {
		var err error
		verifier, err = lookup(arm.Verifier)
		if err != nil {
			return attestationDecision{}, err
		}
	}

	// Run the verifier when one is configured and a token is present. A verifier
	// error is folded into an unverified verdict rather than failing evaluation.
	var verdict *Verdict
	if verifier != nil && attestation.Token != "" {
		var v Verdict
		var err error
		if aa, ok := verifier.(*appleAppAttestVerifier); ok {
			v, err = aa.verifyWithAppID(attestation, arm.AppID)
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
	// verifier, fall back to whether the blob merely claims an attestation —
	// but only when an arm covers this platform at all.
	attested := false
	switch {
	case verdict != nil:
		attested = verdict.Verified
		if arm.RequireHardwareBacked && !verdict.HardwareBacked {

			attested = false
		}
		if arm.RequireTrustedRoot && !verdict.TrustedRoot {

			attested = false
		}
		if arm.RequireVerifiedBoot && !(verdict.VerifiedBootState == "verified" && verdict.DeviceLocked) {

			attested = false
		}
	case hasArm:
		attested = claimsAttestation(attestation)
	}

	switch policy.Mode {
	// Observe: never reject and never shorten the TTL; just record the outcome.
	case AttestationModeObserve:
		return attestationDecision{
			ttl:            baseTtl,
			logAttestation: true,
			verdict:        verdict,
		}, nil

	// Soft: allow either way, but grant only the soft-failure TTL (capped at
	// baseTtl) when the request is not attested.
	case AttestationModeSoft:
		if attested {
			return attestationDecision{ttl: baseTtl, verdict: verdict}, nil
		}

		ttl := softFailureTtl(policy)
		if ttl > baseTtl {
			ttl = baseTtl
		}
		return attestationDecision{ttl: ttl, verdict: verdict}, nil

	// Strict: allow at full TTL when attested, otherwise reject with a reason
	// describing the specific requirement that was not met.
	case AttestationModeStrict:
		if attested {
			return attestationDecision{ttl: baseTtl, verdict: verdict}, nil
		}
		reason := "no attestation claimed"
		if !hasArm {
			reason = fmt.Sprintf(
				"no attestation rule for platform %q on this config",
				attestation.Platform,
			)
		}
		if verdict != nil {
			reason = "verifier rejected: " + verdict.Reason

			if arm.RequireHardwareBacked && !verdict.HardwareBacked {
				reason = "requireHardwareBacked: got " + verdict.SecurityLevel
			}
			if arm.RequireTrustedRoot && !verdict.TrustedRoot {
				reason = "requireTrustedRoot: chain not anchored at a trusted root"
			}
			if arm.RequireVerifiedBoot && !(verdict.VerifiedBootState == "verified" && verdict.DeviceLocked) {
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
		}, nil
	}

	// Unrecognized mode: allow at full TTL.
	return attestationDecision{ttl: baseTtl}, nil
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

// strictDeviceAttestationPolicy returns the policy behind the creator's
// "block rooted/jailbroken devices" choice: strict mode, with one arm per
// platform because the two attestation schemes prove different things.
//
// Android gets android-key-attestation with verified boot demanded — that is
// what actually detects an unlocked bootloader or a modified system image. iOS
// gets apple-app-attest, which requires the app's identity (TEAMID.bundle.id)
// and asserts a Secure Enclave key chaining to Apple's root; it has no
// boot-state concept, so demanding one would reject every iPhone.
//
// An empty iosAppID omits the iOS arm; iOS requests then fail because no
// attestation rule exists for that platform.
func strictDeviceAttestationPolicy(iosAppID string) *AttestationPolicy {
	arms := map[string]*AttestationArm{
		"ANDROID": {
			Verifier:              "android-key-attestation",
			RequireHardwareBacked: true,
			RequireTrustedRoot:    true,
			RequireVerifiedBoot:   true,
		},
	}
	if iosAppID != "" {
		arms["IOS"] = &AttestationArm{
			Verifier:              "apple-app-attest",
			RequireHardwareBacked: true,
			RequireTrustedRoot:    true,
			AppID:                 iosAppID,
		}
	}
	return &AttestationPolicy{
		Mode:      AttestationModeStrict,
		Platforms: arms,
	}
}
