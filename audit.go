package main

import (
	"crypto/sha256"
	"log/slog"
)

// hashDevicePk returns a stable but reversal-resistant identifier for a
// devicePk, suitable for logging. Same (salt, devicePk) → same hash, so
// a creator can correlate events from one device across log lines; same
// devicePk under different salts → different hashes, so logs from
// different creator-servers don't cross-link.
//
// Input: devicePk is the base64url-no-pad string from IssueRequest.DevicePk.
// We decode it to the raw 33 pubkey bytes before hashing — keeps the input
// space tight and ensures the hash matches across format-equivalent
// encodings (e.g. with vs. without padding).
//
// Falls back to hashing the raw string if decode fails — guards against
// crashing on malformed input that may already have failed signature
// verification upstream. The hash is still stable for that input.
func hashDevicePk(salt []byte, devicePkB64 string) string {
	raw, err := b64url.DecodeString(devicePkB64)
	if err != nil {
		// Fall back to hashing the string verbatim.
		raw = []byte(devicePkB64)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write(raw)
	return b64url.EncodeToString(h.Sum(nil))
}

// auditEmit writes one structured audit record via slog. Single funnel
// for issuance-related events so the schema stays consistent and so
// the devicePk hashing happens once, in one place.
//
// Fields:
//   event           — "issue.granted", "issue.rate_limited",
//                     "issue.attestation_rejected", "issue.attestation_observed".
//   devicePkB64     — raw IssueRequest.DevicePk; will be hashed before log.
//   configID        — IssueRequest.ConfigID; the routing key, shortened
//                     for log readability via shortBase64 in the caller.
//   policyMode      — "off"/"observe"/"soft"/"strict" or "" if no policy.
//   claimedPlatform — req.Attestation.Platform.
//   tokenPresent    — req.Attestation.Token != "".
//   ttlSec          — credential TTL in seconds (0 if rejected).
//   extras          — optional event-specific fields. Passed through verbatim;
//                     callers should NOT include raw devicePks or IPs here.
//
// What this function deliberately does NOT log:
//   - The raw devicePk string. Hashed via hashDevicePk before emit.
//   - The client's IP address. The HTTP layer has it but we don't pass it
//     down; opt-in mechanism deferred if needed.
//   - Session credentials, request signatures, attestation tokens — anything
//     that's a secret or could be replayed.
func auditEmit(
	logger *slog.Logger,
	salt []byte,
	event string,
	devicePkB64 string,
	configID string,
	policyMode string,
	claimedPlatform string,
	tokenPresent bool,
	ttlSec int,
	extras ...any,
) {
	attrs := []any{
		"event", event,
		"devicePkHash", hashDevicePk(salt, devicePkB64),
		"configId", configID,
		"claimedPlatform", claimedPlatform,
		"tokenPresent", tokenPresent,
		"policyMode", policyMode,
		"ttlSec", ttlSec,
	}
	attrs = append(attrs, extras...)
	logger.Info("audit", attrs...)
}
