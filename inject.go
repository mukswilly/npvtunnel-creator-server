package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// credentialSentinel is the literal string an operator places into the
// ConfigEntry.Config template wherever the issuer should inject the
// HMAC-derived session credential. Substitution is a string-match on
// JSON leaves only (not keys), so the sentinel is safe to use anywhere
// a string value is expected (V2rayProfile.password, SshConfig.sshPassword,
// etc.).
//
// Chosen to be visually distinct from anything that could appear naturally
// in a config and to be easy to grep for in configs.json files.
const credentialSentinel = "$NPVT_CREDENTIAL$"

// Recognized values for ConfigEntry.CredentialEncoding. Used by
// encodeCredential to render HMAC bytes into the wire form a given
// protocol expects in its credential slot.
const (
	// credEncodingUuidV4 renders 16 HMAC bytes as a canonical RFC 4122
	// UUIDv4 string ("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"). Use this
	// for VLESS/VMess id slots — xray-core validates UUID format on
	// these fields.
	credEncodingUuidV4 = "uuid-v4"

	// credEncodingBase64UrlRaw renders all 32 HMAC bytes as base64url-no-pad.
	// Use this for SSH password slots and anything else that accepts an
	// opaque high-entropy string.
	credEncodingBase64UrlRaw = "base64url-raw"
)

func validCredentialEncoding(s string) bool {
	switch s {
	case credEncodingUuidV4, credEncodingBase64UrlRaw, "":
		return true
	}
	return false
}

// deriveCredentialBytes computes the HMAC-bound credential bytes the
// issuer + VPN data plane share. Same construction as the legacy
// deriveSessionCred — kept identical so a deployed VPN
// server doesn't have to learn a second derivation:
//
//	bytes = HMAC-SHA256(vpnHmacKey, "v1.cred|" + devicePk + "|" + expiresAt)
//
// The encoding into a wire-shaped credential happens separately in
// encodeCredential.
func deriveCredentialBytes(vpnHmacKey []byte, devicePk, expiresAt string) []byte {
	mac := hmac.New(sha256.New, vpnHmacKey)
	mac.Write([]byte(sessionCredPrefix))
	mac.Write([]byte(devicePk))
	mac.Write([]byte("|"))
	mac.Write([]byte(expiresAt))
	return mac.Sum(nil)
}

// encodeCredential renders the HMAC bytes per the configured encoding.
// Empty encoding falls back to base64url-raw for forgiveness — an
// operator-side typo on the encoding name surfaces at configs.json load
// time, not here.
func encodeCredential(encoding string, hmacBytes []byte) (string, error) {
	switch encoding {
	case credEncodingUuidV4:
		if len(hmacBytes) < 16 {
			return "", fmt.Errorf("uuid-v4 needs >=16 hmac bytes, got %d", len(hmacBytes))
		}
		return uuidV4FromBytes(hmacBytes[:16]), nil
	case credEncodingBase64UrlRaw, "":
		return b64url.EncodeToString(hmacBytes), nil
	default:
		return "", fmt.Errorf("unknown credentialEncoding %q", encoding)
	}
}

// uuidV4FromBytes formats 16 bytes as an RFC 4122 UUIDv4 string. The
// version (top 4 bits of byte 6) and variant (top 2 bits of byte 8)
// fields are forced regardless of input — the input here is HMAC output
// so the masked bits are uniformly random, but we don't rely on that.
func uuidV4FromBytes(b []byte) string {
	if len(b) < 16 {
		panic("uuidV4FromBytes: <16 bytes")
	}
	out := make([]byte, 16)
	copy(out, b[:16])
	out[6] = (out[6] & 0x0f) | 0x40
	out[8] = (out[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		out[0:4], out[4:6], out[6:8], out[8:10], out[10:16])
}

// injectCredential walks the JSON tree at `raw` and replaces every
// string leaf whose value equals [credentialSentinel] with `encoded`.
// Recurses into objects and arrays; non-string leaves and object keys
// are left untouched.
//
// Returns the substituted JSON bytes. Re-marshalled, not the original
// bytes — JSON object key order may shift to Go's map iteration order.
// That's fine: the canonical-bytes guarantee is provided by the receipt
// signature input (which signs over the post-substitution configB64),
// not by the JSON internal ordering.
func injectCredential(raw json.RawMessage, encoded string) (json.RawMessage, error) {
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}
	substituteSentinel(&tree, encoded)
	return json.Marshal(tree)
}

// substituteSentinel recursively walks v, replacing strings equal to
// credentialSentinel with encoded. Mutates in place via the pointer so
// the caller's `any` value receives the substituted leaves.
func substituteSentinel(v *any, encoded string) {
	switch x := (*v).(type) {
	case string:
		if x == credentialSentinel {
			*v = encoded
		}
	case []any:
		for i := range x {
			substituteSentinel(&x[i], encoded)
		}
	case map[string]any:
		for k, e := range x {
			ev := e
			substituteSentinel(&ev, encoded)
			x[k] = ev
		}
	}
}
