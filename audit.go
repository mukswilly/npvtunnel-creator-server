package main

import (
	"crypto/sha256"
	"log/slog"
)

// hashDevicePk returns a salted SHA-256 of a device public key, so audit logs
// can correlate a device across events without recording the raw key. Inputs
// that aren't valid base64url are hashed as-is.
func hashDevicePk(salt []byte, devicePkB64 string) string {
	raw, err := b64url.DecodeString(devicePkB64)
	if err != nil {

		raw = []byte(devicePkB64)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write(raw)
	return b64url.EncodeToString(h.Sum(nil))
}

// auditEmit writes one structured audit record. The device key is salted-hashed;
// the remaining positional fields are the common dimensions shared by every
// event, and extras are appended as additional key/value pairs.
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
